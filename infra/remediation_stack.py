# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""AWS CDK stack for the self-correcting dependency remediation agent.

Flow: a client uploads requests/<project>/<run-id>/source.zip to the bucket ->
S3 emits an Object Created event to EventBridge -> the trigger function invokes
the agent on Amazon Bedrock AgentCore Runtime -> the agent upgrades, builds in
CodeBuild, repairs, and writes results/<project>/<run-id>/{result.json,fix.patch,report.md}
-> a "Remediation Completed" event is published (and optionally emailed).

The agent holds no source-control credentials. The client's own pipeline
applies fix.patch and opens the merge request or pull request.
"""

from __future__ import annotations

from pathlib import Path

from aws_cdk import BundlingOptions, CfnOutput, Duration, RemovalPolicy, Stack, Token
from aws_cdk import aws_bedrock as bedrock
from aws_cdk import aws_bedrockagentcore as agentcore
from aws_cdk import aws_codebuild as codebuild
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sns_subscriptions as subscriptions
from aws_cdk import aws_sqs as sqs
from constructs import Construct

ROOT = Path(__file__).resolve().parent.parent
MEMORY_NAMESPACE_TEMPLATE = "remediation/{actorId}"
EVENT_SOURCE = "dependency.remediation"

# Build commands run in CodeBuild. The build script itself (.remediation/build.sh)
# is packaged into the source archive by the agent code; see build_runner.py.
BUILDSPEC = {
    "version": "0.2",
    "phases": {
        "install": {"runtime-versions": {"python": "3.12", "nodejs": "20", "java": "corretto21"}},
        "build": {"commands": ["bash .remediation/build.sh"]},
        "post_build": {
            "commands": [
                # Upload regenerated lockfiles so the agent can include them in the patch.
                'for f in $LOCKFILES; do p="$APP_DIR/$f"; if [ -f "$p" ]; then aws s3 cp "$p" "$OUTPUT_PREFIX/$f" --sse aws:kms --only-show-errors; fi; done',
            ]
        },
    },
}


# Cross-Region inference profile prefixes and the Region name prefixes they can be called from.
# Model IDs without one of these prefixes (in-Region model IDs) are not checked.
INFERENCE_PROFILE_GEOGRAPHIES = {
    "us.": ("us-", "ca-"),
    "us-gov.": ("us-gov-",),
    "eu.": ("eu-",),
    "apac.": ("ap-",),
    "jp.": ("ap-",),
    "au.": ("ap-",),
    "ca.": ("ca-",),
    "global.": ("",),
}


def model_resources(model_id: str, region: str, account: str) -> list[str]:
    """IAM resources for invoking exactly one model (directly or through its inference profile).

    A cross-Region profile routes to the same foundation model in other Regions of its geography,
    so the foundation-model ARN keeps a Region wildcard. The global profile uses foundation-model
    ARNs with an empty Region, which the wildcard also matches.
    """
    for prefix in INFERENCE_PROFILE_GEOGRAPHIES:
        if model_id.startswith(prefix):
            base = model_id[len(prefix):]
            return [
                f"arn:aws:bedrock:{region}:{account}:inference-profile/{model_id}",
                f"arn:aws:bedrock:*::foundation-model/{base}",
            ]
    return [f"arn:aws:bedrock:{region}::foundation-model/{model_id}"]  # in-Region model ID


def check_model_region(model_id: str | None, region: str) -> None:
    """Fail at synth time if the inference profile cannot be used from the deployment Region."""
    if not model_id:
        raise ValueError("No model configured. Set AWS_REGION (the model is then chosen automatically) or MODEL_ID in .env, or pass -c model_id=<model or inference profile>.")
    if Token.is_unresolved(region):
        return  # environment-agnostic synth: the Region is known only at deploy time
    for prefix, region_prefixes in INFERENCE_PROFILE_GEOGRAPHIES.items():
        if model_id.startswith(prefix):
            us_profile_in_govcloud = prefix == "us." and region.startswith("us-gov-")
            if not any(region.startswith(rp) for rp in region_prefixes) or us_profile_in_govcloud:
                raise ValueError(
                    f"model_id '{model_id}' is a '{prefix}' cross-Region inference profile and cannot be used in {region}. "
                    f"Deploy with a matching profile, for example: cdk deploy -c model_id=<profile for {region}>"
                )
            return


class RemediationStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        cfg = self.node.try_get_context
        runtime_name = cfg("runtime_name") or "dependency_remediation_agent"
        model_id = cfg("model_id")
        region, account = self.region, self.account
        check_model_region(model_id, region)

        # ----- Storage: requests in, results out -------------------------------
        bucket = s3.Bucket(
            self,
            "ArtifactBucket",
            encryption=s3.BucketEncryption.KMS_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            lifecycle_rules=[
                s3.LifecycleRule(id="requests", prefix="requests/", expiration=Duration.days(14)),
                s3.LifecycleRule(id="builds", prefix="runs/", expiration=Duration.days(14)),
                s3.LifecycleRule(id="results", prefix="results/", expiration=Duration.days(90)),
            ],
            # Retained on stack deletion. This avoids the CDK auto-delete helper function, whose
            # role needs s3:DeleteObject* and s3:PutBucketPolicy on the bucket. Objects expire
            # through the lifecycle rules; delete the empty bucket manually if no longer needed.
            removal_policy=RemovalPolicy.RETAIN,
        )
        # Turn on S3 -> EventBridge delivery with the native CloudFormation property, instead of
        # event_bridge_enabled=True, which deploys a helper function with AWSLambdaBasicExecutionRole.
        bucket.node.default_child.add_property_override("NotificationConfiguration.EventBridgeConfiguration.EventBridgeEnabled", True)
        runs = dynamodb.Table(
            self,
            "RemediationRuns",
            partition_key=dynamodb.Attribute(name="pk", type=dynamodb.AttributeType.STRING),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="expires_at",
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(point_in_time_recovery_enabled=True),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # ----- Isolated build environment -------------------------------------
        build_logs = logs.LogGroup(self, "BuildLogs", retention=logs.RetentionDays.ONE_MONTH, removal_policy=RemovalPolicy.DESTROY)
        # Our own role, passed to CodeBuild as immutable, so CDK cannot add its default grants
        # (the /aws/codebuild/* log groups and test-report groups, which this project never uses).
        build_role = iam.Role(
            self,
            "BuildRole",
            assumed_by=iam.ServicePrincipal("codebuild.amazonaws.com", conditions={"StringEquals": {"aws:SourceAccount": account}}),
            description="CodeBuild role for remediation builds: read build archives, write lockfiles and its own logs",
        )
        build_role.attach_inline_policy(
            iam.Policy(
                self,
                "BuildPolicy",
                statements=[
                    iam.PolicyStatement(sid="ReadBuildArchives", actions=["s3:GetObject", "s3:GetObjectVersion"], resources=[bucket.arn_for_objects("runs/*")]),
                    iam.PolicyStatement(sid="BucketLocation", actions=["s3:GetBucketAcl", "s3:GetBucketLocation"], resources=[bucket.bucket_arn]),
                    iam.PolicyStatement(sid="WriteLockfiles", actions=["s3:PutObject"], resources=[bucket.arn_for_objects("runs/*/output/*")]),
                    iam.PolicyStatement(sid="WriteBuildLogs", actions=["logs:CreateLogStream", "logs:PutLogEvents"], resources=[build_logs.log_group_arn]),
                ],
            )
        )
        project = codebuild.Project(
            self,
            "BuildProject",
            description="Runs untrusted repository builds and tests for the remediation agent",
            # No project source: each StartBuild call supplies an S3 source override
            # (sourceTypeOverride=S3), so CDK does not add a broad bucket read grant.
            build_spec=codebuild.BuildSpec.from_object(BUILDSPEC),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2023_5,
                compute_type=codebuild.ComputeType.MEDIUM,
            ),
            timeout=Duration.minutes(30),
            queued_timeout=Duration.minutes(30),
            logging=codebuild.LoggingOptions(cloud_watch=codebuild.CloudWatchLoggingOptions(log_group=build_logs)),
            # The build role can read build archives and write lockfiles only. It cannot read
            # requests or results, the DynamoDB table, or the model.
            role=build_role.without_policy_updates(),
        )
        project.node.add_dependency(build_role)

        # ----- Guardrail -------------------------------------------------------
        guardrail = bedrock.CfnGuardrail(
            self,
            "Guardrail",
            name=f"{construct_id}-guardrail",
            description="Filters prompt attacks in untrusted repository content",
            blocked_input_messaging="The request was blocked by the remediation guardrail.",
            blocked_outputs_messaging="The response was blocked by the remediation guardrail.",
            content_policy_config=bedrock.CfnGuardrail.ContentPolicyConfigProperty(
                filters_config=[
                    bedrock.CfnGuardrail.ContentFilterConfigProperty(type="PROMPT_ATTACK", input_strength="HIGH", output_strength="NONE"),
                ]
            ),
        )
        guardrail_version = bedrock.CfnGuardrailVersion(self, "GuardrailVersion", guardrail_identifier=guardrail.attr_guardrail_id)

        # ----- Long-term memory -----------------------------------------------
        memory = agentcore.CfnMemory(
            self,
            "FixMemory",
            name=f"{runtime_name}_memory",
            description="Successful dependency fixes, reused across projects",
            event_expiry_duration=90,
            memory_strategies=[
                agentcore.CfnMemory.MemoryStrategyProperty(
                    semantic_memory_strategy=agentcore.CfnMemory.SemanticMemoryStrategyProperty(
                        name="fix_recipes", description="Reusable facts about library upgrades and code changes", namespaces=[MEMORY_NAMESPACE_TEMPLATE]
                    )
                )
            ],
        )

        # ----- Completion notifications ---------------------------------------
        # The agent publishes a plain-text summary directly (an EventBridge input transformer
        # can only produce JSON or quoted lines). The "Remediation Completed" event is still
        # published on the default bus for other integrations.
        topic = sns.Topic(self, "CompletionTopic", display_name="Dependency remediation results", enforce_ssl=True)
        if email := cfg("notification_email"):
            topic.add_subscription(subscriptions.EmailSubscription(email))

        # ----- Agent runtime ---------------------------------------------------
        image = ecr_assets.DockerImageAsset(self, "AgentImage", directory=str(ROOT / "agent"), platform=ecr_assets.Platform.LINUX_ARM64)
        runtime_role = iam.Role(
            self,
            "AgentRuntimeRole",
            assumed_by=iam.ServicePrincipal(
                "bedrock-agentcore.amazonaws.com",
                conditions={
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account}:*"},
                },
            ),
        )
        image.repository.grant_pull(runtime_role)
        runtime_policy = iam.Policy(
            self,
            "AgentRuntimePolicy",
            statements=[
                iam.PolicyStatement(
                    actions=["logs:CreateLogGroup", "logs:DescribeLogStreams", "logs:CreateLogStream", "logs:PutLogEvents"],
                    # Only this runtime's log groups (/aws/bedrock-agentcore/runtimes/<runtime-id>-<endpoint>).
                    resources=[
                        f"arn:aws:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/runtimes/{runtime_name}-*",
                        f"arn:aws:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/runtimes/{runtime_name}-*:log-stream:*",
                    ],
                ),
                iam.PolicyStatement(actions=["logs:DescribeLogGroups"], resources=[f"arn:aws:logs:{region}:{account}:log-group:*"]),
                iam.PolicyStatement(
                    actions=["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"],
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    actions=["cloudwatch:PutMetricData"],
                    resources=["*"],
                    conditions={"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}},
                ),
                iam.PolicyStatement(
                    actions=["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                    # Only the configured model and its inference profile, not every model.
                    resources=model_resources(model_id, region, account),
                ),
                iam.PolicyStatement(actions=["bedrock:ApplyGuardrail"], resources=[guardrail.attr_guardrail_arn]),
                iam.PolicyStatement(
                    actions=["bedrock-agentcore:CreateEvent", "bedrock-agentcore:RetrieveMemoryRecords"],
                    resources=[memory.attr_memory_arn],
                ),
                iam.PolicyStatement(actions=["codebuild:StartBuild", "codebuild:BatchGetBuilds", "codebuild:StopBuild"], resources=[project.project_arn]),
                # log_group_arn already ends in ":*", which covers the group's log streams.
                iam.PolicyStatement(actions=["logs:GetLogEvents"], resources=[build_logs.log_group_arn]),
                iam.PolicyStatement(
                    actions=["events:PutEvents"],
                    resources=[f"arn:aws:events:{region}:{account}:event-bus/default"],
                    conditions={"StringEquals": {"events:source": EVENT_SOURCE}},
                ),
                iam.PolicyStatement(sid="SendCompletionEmail", actions=["sns:Publish"], resources=[topic.topic_arn]),
            ],
        )
        runtime_policy.attach_to_role(runtime_role)
        runtime_role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadSourceAndLockfiles",
                actions=["s3:GetObject"],
                resources=[bucket.arn_for_objects("requests/*"), bucket.arn_for_objects("runs/*/output/*")],
            )
        )
        runtime_role.add_to_policy(
            iam.PolicyStatement(
                sid="WriteBuildsAndResults",
                actions=["s3:PutObject"],
                resources=[bucket.arn_for_objects("runs/*"), bucket.arn_for_objects("results/*")],
            )
        )
        # Listing (prefix-scoped) lets S3 answer 404 instead of 403 when a build produced no lockfile.
        runtime_role.add_to_policy(
            iam.PolicyStatement(
                sid="ListBuildOutputs",
                actions=["s3:ListBucket"],
                resources=[bucket.bucket_arn],
                conditions={"StringLike": {"s3:prefix": ["runs/*"]}},
            )
        )
        runtime_role.add_to_policy(
            iam.PolicyStatement(
                sid="UpdateRunRecords",
                actions=["dynamodb:UpdateItem"],
                resources=[runs.table_arn],
                conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["run#*"]}},
            )
        )

        runtime = agentcore.CfnRuntime(
            self,
            "AgentRuntime",
            agent_runtime_name=runtime_name,
            description="Self-correcting dependency remediation agent (Strands Agents)",
            role_arn=runtime_role.role_arn,
            agent_runtime_artifact=agentcore.CfnRuntime.AgentRuntimeArtifactProperty(
                container_configuration=agentcore.CfnRuntime.ContainerConfigurationProperty(container_uri=image.image_uri)
            ),
            network_configuration=agentcore.CfnRuntime.NetworkConfigurationProperty(network_mode="PUBLIC"),
            lifecycle_configuration=agentcore.CfnRuntime.LifecycleConfigurationProperty(idle_runtime_session_timeout=900, max_lifetime=28800),
            environment_variables={
                "REMEDIATION_REGION": region,
                "MODEL_ID": model_id,
                "GUARDRAIL_ID": guardrail.attr_guardrail_id,
                "GUARDRAIL_VERSION": guardrail_version.attr_version,
                "MEMORY_ID": memory.attr_memory_id,
                "RUNS_TABLE": runs.table_name,
                "ARTIFACT_BUCKET": bucket.bucket_name,
                "CODEBUILD_PROJECT": project.project_name,
                "EVENT_BUS": "default",
                "NOTIFICATION_TOPIC_ARN": topic.topic_arn,
                "BUILD_BACKEND": "codebuild",
                "MAX_BUILD_ATTEMPTS": str(cfg("max_build_attempts") or 6),
                "MAX_FILES_CHANGED": str(cfg("max_files_changed") or 20),
                "MAX_TOOL_CALLS": str(cfg("max_tool_calls") or 100),
                "BUILD_TIMEOUT_SECONDS": "1800",
                "AGENT_OBSERVABILITY_ENABLED": "true",
            },
        )
        runtime.node.add_dependency(runtime_policy)
        runtime.node.add_dependency(runtime_role)

        # ----- Trigger: S3 upload -> EventBridge -> Lambda -> agent ------------
        trigger_dir = ROOT / "functions" / "trigger"
        trigger_logs = logs.LogGroup(self, "TriggerLogs", retention=logs.RetentionDays.ONE_MONTH, removal_policy=RemovalPolicy.DESTROY)
        # Own role instead of AWSLambdaBasicExecutionRole, which allows CloudWatch Logs on "*".
        trigger_role = iam.Role(
            self,
            "TriggerRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com", conditions={"StringEquals": {"aws:SourceAccount": account}}),
            description="Trigger function role: validate uploads and start remediation runs",
        )
        trigger_role.add_to_policy(
            iam.PolicyStatement(sid="WriteOwnLogs", actions=["logs:CreateLogStream", "logs:PutLogEvents"], resources=[trigger_logs.log_group_arn])
        )
        # One dead-letter queue catches both EventBridge delivery failures (target DLQ) and
        # function errors after Lambda's asynchronous retries (function DLQ).
        dlq = sqs.Queue(self, "TriggerDLQ", retention_period=Duration.days(14), enforce_ssl=True, encryption=sqs.QueueEncryption.SQS_MANAGED)
        trigger = lambda_.Function(
            self,
            "TriggerFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            architecture=lambda_.Architecture.ARM_64,
            handler="handler.handler",
            code=lambda_.Code.from_asset(
                str(trigger_dir),
                bundling=BundlingOptions(
                    image=lambda_.Runtime.PYTHON_3_12.bundling_image,
                    platform="linux/arm64",
                    command=["bash", "-c", "pip install --no-cache-dir -r requirements.txt -t /asset-output --quiet && cp handler.py /asset-output/"],
                ),
            ),
            timeout=Duration.seconds(60),
            memory_size=256,
            dead_letter_queue=dlq,
            reserved_concurrent_executions=int(cfg("max_concurrent_runs") or 10),
            role=trigger_role,
            environment={
                "ARTIFACT_BUCKET": bucket.bucket_name,
                "RUNS_TABLE": runs.table_name,
                "AGENT_RUNTIME_ARN": runtime.attr_agent_runtime_arn,
                "MAX_ARCHIVE_MB": str(cfg("max_archive_mb") or 200),
            },
            log_group=trigger_logs,
        )
        # Items are keyed run#<id>; the condition stops the role from writing any other key.
        trigger.add_to_role_policy(
            iam.PolicyStatement(
                sid="CreateRunRecords",
                actions=["dynamodb:PutItem"],
                resources=[runs.table_arn],
                conditions={"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["run#*"]}},
            )
        )
        trigger.add_to_role_policy(iam.PolicyStatement(actions=["s3:GetObject"], resources=[bucket.arn_for_objects("requests/*")]))
        trigger.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock-agentcore:InvokeAgentRuntime"],
                resources=[runtime.attr_agent_runtime_arn, f"{runtime.attr_agent_runtime_arn}/*"],
            )
        )

        events.Rule(
            self,
            "SourceUploadedRule",
            description="Start a remediation run when a source archive is uploaded under requests/",
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["Object Created"],
                detail={"bucket": {"name": [bucket.bucket_name]}, "object": {"key": [{"prefix": "requests/"}]}},
            ),
            targets=[targets.LambdaFunction(trigger, dead_letter_queue=dlq, retry_attempts=2, max_event_age=Duration.hours(2))],
        )

        # ----- Client access: attach this policy to CI roles or developers -----
        client_policy = iam.ManagedPolicy(
            self,
            "ClientPolicy",
            description="Upload source archives for remediation and read the results",
            statements=[
                iam.PolicyStatement(actions=["s3:PutObject"], resources=[bucket.arn_for_objects("requests/*")]),
                iam.PolicyStatement(actions=["s3:GetObject"], resources=[bucket.arn_for_objects("results/*")]),
                iam.PolicyStatement(
                    actions=["s3:ListBucket"],
                    resources=[bucket.bucket_arn],
                    conditions={"StringLike": {"s3:prefix": ["results/*"]}},
                ),
                iam.PolicyStatement(actions=["cloudformation:DescribeStacks"], resources=[self.stack_id]),
            ],
        )

        # ----- Outputs ---------------------------------------------------------
        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "ClientPolicyArn", value=client_policy.managed_policy_arn)
        CfnOutput(self, "AgentRuntimeArn", value=runtime.attr_agent_runtime_arn)
        CfnOutput(self, "RunsTableName", value=runs.table_name)
        CfnOutput(self, "CompletionTopicArn", value=topic.topic_arn)
        CfnOutput(self, "BuildProjectName", value=project.project_name)
