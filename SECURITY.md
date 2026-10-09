# Security Policy

## Disclaimer

This project is provided as sample code for an AWS Prescriptive Guidance pattern. It is **not** intended for
production use without the additional hardening described in [Production hardening recommendations](#production-hardening-recommendations).
You are responsible for reviewing the code, the infrastructure, and the AI-generated changes it produces
against your own security, compliance, and data-handling requirements.

## Reporting vulnerabilities

If you discover a potential security issue in this project, notify AWS/Amazon Security through the
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/) or by email to
aws-security@amazon.com. Do **not** report security vulnerabilities through public issues.

## Threat model summary

| Asset | Threat | Primary controls |
|---|---|---|
| Customer source code in the uploaded archive | Unauthorized read or write | Private, TLS-only, KMS-encrypted S3 bucket; uploads and reads only through the scoped client policy; 14-day expiry of requests |
| Agent runtime and its IAM role | Prompt injection from repository content steering the agent | Guardrail prompt-attack filter; system prompt treats repository content as untrusted; all actions go through tools with code-enforced guards; no source-control or secret access |
| Build environment | Malicious install scripts or tests in the repository | Builds run in AWS CodeBuild, not in the agent; build role can only read its build archive and write lockfiles; no privileged mode; 30-minute timeout |
| Agent host | Archive path traversal, symlinks, compression bombs | Regular files only; every path resolved inside the workspace; streaming extraction with a size limit; size checked before download |
| Internal network endpoints | Server-side request forgery through crafted package names or redirects | Outbound HTTP limited to four HTTPS registry hosts; every redirect and final URL checked; Maven coordinates validated |
| Customer repositories | Unreviewed changes | The agent cannot push or merge. It returns a patch; the customer's pipeline opens a review that a human approves |
| AWS bill | Runaway loops or floods of uploads | Per-run budgets (build attempts, tool calls, changed files); trigger concurrency limit; archive size limit; lifecycle expiry |

## AWS services used

- **Amazon Bedrock** (Anthropic Claude Sonnet, cross-Region inference profile): agent reasoning. **Amazon Bedrock Guardrails**: prompt-attack filtering.
- **Amazon Bedrock AgentCore**: Runtime hosts the agent container; Memory stores reusable fix summaries; Observability sends traces to CloudWatch.
- **Amazon S3**: uploaded source archives (`requests/`), build archives (`runs/`), and results (`results/`).
- **Amazon EventBridge**: S3 upload events start runs; the agent publishes a "Remediation Completed" event on the default bus for other integrations.
- **AWS Lambda**: trigger function that validates the upload and invokes the agent.
- **Amazon DynamoDB**: run records and duplicate-event protection.
- **AWS CodeBuild**: isolated dependency installation and unit tests.
- **Amazon SNS**: the agent publishes a plain-text summary of each completed run (optional email subscription). **Amazon SQS**: dead-letter queue for failed trigger events.
- **Amazon CloudWatch Logs and AWS X-Ray**: logs and traces.
- **Amazon ECR**: agent container image (CDK asset repository).
- **AWS IAM**: service roles and the client policy.

External endpoints called by the agent: `api.osv.dev`, `pypi.org`, `registry.npmjs.org`, `repo1.maven.org`.
CodeBuild also downloads packages from the public registries that the project's build uses.

## Security controls implemented

- No source-control credentials anywhere in the solution. The agent returns a patch and cannot push, merge, or open reviews.
- No public endpoints. The agent runtime accepts only IAM-authenticated invocations, and the trigger function is invoked only by EventBridge.
- S3 bucket: Block Public Access (all four settings), TLS enforced by bucket policy, SSE-KMS, lifecycle expiry (requests 14 days, build archives 14 days, results 90 days).
- Least-privilege IAM, scoped by resource and S3 prefix:
  - Agent role: `GetObject` on `requests/*` and `runs/*/output/*`, `PutObject` on `runs/*` and `results/*`, `ListBucket` only for the `runs/` prefix, one CodeBuild project, one memory (`CreateEvent`, `RetrieveMemoryRecords`), one guardrail, one model and its inference profile, `UpdateItem` on `run#` items of one table, `PutEvents` on the default bus only for its own event source, `Publish` to the completion topic.
  - S3 grants are written as explicit object-level statements, not CDK `grant_read`/`grant_put`, so no role gets `s3:List*`, `s3:GetBucket*`, or object legal-hold and retention actions on the bucket. `tests/test_least_privilege.py` enforces this.
  - Build role: `GetObject` on `runs/*`, `PutObject` on `runs/*/output/*`, `GetBucketAcl`/`GetBucketLocation` on the bucket, write its own log group.
  - Trigger role: `GetObject` on `requests/*`, `PutItem` on one table, `SendMessage` to its dead-letter queue, invoke one agent runtime.
  - Client policy: write `requests/*`, read `results/*`, list `results/*`, `DescribeStacks` on this stack (to find the bucket).
- Every role is trusted only by its service and only from this account (`aws:SourceAccount`; the runtime role also uses `aws:SourceArn`). No role uses an AWS managed policy such as `AWSLambdaBasicExecutionRole`, which allows CloudWatch Logs on `*`.
- Each role writes only to its own log group. The agent's log permissions are scoped to its own runtime's log groups.
- DynamoDB writes are limited to `run#` items with a `dynamodb:LeadingKeys` condition.
- Resource policies are bound to their source: the dead-letter queue accepts EventBridge messages only from its own rule, and the function accepts invocations only from its rule. The SNS topic grants no service principal; only the agent role can publish to it, through IAM, and the topic policy denies non-TLS requests.
- No CDK helper functions are deployed: S3 to EventBridge delivery uses the native bucket property, and the bucket is retained instead of emptied by a function on deletion.
- Amazon Bedrock Guardrail (prompt attack, HIGH) on every model invocation, evaluated on the latest message.
- System prompt instructs the model to treat all repository content and build logs as untrusted data.
- Tool guards enforced in code: workspace path confinement, symlink escape protection, protected paths (`.git/`, `.github/`, `.gitlab-ci.yml`, `.circleci/`, `Jenkinsfile`, `buildspec*`, `CODEOWNERS`, `.remediation/`), 200 KB write limit, changed-file budget, build-attempt budget, tool-call budget, target versions must be newer, published, and free of known advisories.
- A patch is published only if the latest build passed and the workspace fingerprint is unchanged since that build.
- Input validation: S3 key layout, project name, run ID, `app_dir` character set, package names, Maven coordinates, archive size (event, `HeadObject`, and downloaded file), extracted size, response size.
- Archive extraction: regular files only (no symlinks, hard links, or devices), every path resolved inside the workspace, streamed to disk.
- Outbound HTTP allowlist with redirect checks; HTTPS only.
- Duplicate-run protection with a DynamoDB conditional write; failed trigger events go to an encrypted dead-letter queue.
- Container runs as a non-root user; CodeBuild privileged mode is off.
- Dependencies pinned to exact versions (`pyproject.toml`, `uv.lock` with hashes, `agent/requirements.txt`, `functions/trigger/requirements.txt`).
- Supply-chain cooldown: `exclude-newer = "7 days"` in `pyproject.toml`, so uv never resolves a package version published in the last 7 days. All pinned versions are at least 7 days old.
- GitHub Actions in the CI template are pinned to full commit SHAs, not mutable tags.
- Registry XML (Maven metadata) is parsed with `defusedxml`, which blocks entity expansion, external entities, and DTD retrieval.
- The trigger function has a function-level dead-letter queue in addition to the EventBridge target dead-letter queue.
- The agent container defines a `HEALTHCHECK` against the runtime `/ping` endpoint.
- Every run, including failures, is recorded in DynamoDB and in `result.json`.
- SPDX license identifiers on all source files.
- Unit and security regression tests (`tests/test_security.py`) for path traversal, symlinks, compression bombs, SSRF, shell metacharacters, patch integrity, and lockfile encoding.

## Known security considerations

| ID | Item | Category | Status |
|---|---|---|---|
| SD-1 | S3 bucket uses the AWS managed KMS key (`aws/s3`), not a customer managed key | Security debt | Accepted |
| SD-2 | DynamoDB, CloudWatch Logs, SNS, and AgentCore Memory use AWS owned or default encryption, not a customer managed key | Security debt | Accepted |
| SD-3 | Agent runtime uses `PUBLIC` network mode | Deployment concern | Documented |
| SD-4 | CodeBuild runs untrusted repository code with outbound internet access and no VPC | Security debt | Accepted |
| SD-5 | Some IAM statements use `*` resources | Security debt | Documented |
| SD-6 | The client policy does not isolate projects from each other | Deployment concern | Documented |
| SD-7 | Source code is sent to Amazon Bedrock through a cross-Region inference profile | Data handling | Documented |
| SD-8 | The guardrail filters prompt attacks on input only | Security debt | Accepted |
| SD-9 | AI-generated changes can be incorrect | Residual risk | Documented |
| SD-10 | Removal policies delete data on `cdk destroy`; no S3 versioning or access logging | Security debt | Accepted |
| SD-11 | Packages come from public registries | Supply chain | Documented |
| SD-12 | No per-caller rate limit | Security debt | Accepted |
| SD-13 | Lambda functions do not run in a VPC | Security debt | Accepted |

## Security scanning

The repository is scanned with [AWS Automated Security Helper (ASH)](https://github.com/awslabs/automated-security-helper)
v3.5.8 in container mode. All 10 scanners pass with no actionable findings at MEDIUM severity or above:

| Scanner | Scope | Result |
|---|---|---|
| bandit | Python source | Passed (131 suppressed: `assert` in tests, reviewed `subprocess` use) |
| cdk-nag | CloudFormation template | Passed |
| cfn-nag | CloudFormation template | Passed |
| checkov | Template, Dockerfile, CI workflows | Passed (9 suppressed, each mapped to an SD item or a false positive) |
| detect-secrets | All files | Passed |
| grype | Dependency vulnerabilities | Passed |
| npm-audit | Node.js dependencies | Passed |
| opengrep, semgrep | Code and configuration patterns | Passed |
| syft | Software bill of materials | Passed |

- Configuration, ignored paths, and every suppression with its reason: [`.ash/.ash.yaml`](.ash/.ash.yaml). All suppressions are in use.
- Reports: [`docs/security/ash-summary.md`](docs/security/ash-summary.md) and [`docs/security/ash-report.html`](docs/security/ash-report.html).
- Reviewed `subprocess` calls are marked inline with `# nosec` and a justification.

To reproduce:

```bash
uv run cdk synth --quiet
uvx --from git+https://github.com/awslabs/automated-security-helper.git@v3.5.8 ash --mode container
```

Scan findings that were fixed rather than suppressed: XML parsing with `xml.etree` (now `defusedxml`), GitHub Actions
pinned by tag (now by commit SHA), no uv dependency cooldown (now 7 days), no container `HEALTHCHECK` (added), no
function-level dead-letter queue on the trigger function (added), and a vulnerable transitive `pyjwt` 2.14.0
(GHSA-42vr-xj54-vc7v, through `strands-agents` and `mcp`; now constrained to 2.15.1 or later).

## Production hardening recommendations

- **Encryption:** use customer managed KMS keys for the bucket, table, log groups, SNS topic, and AgentCore Memory (SD-1, SD-2).
- **Network:** run the agent runtime in `VPC` network mode and CodeBuild in a VPC, with egress through a proxy or firewall that allows only the model endpoint and the package registries you use (SD-3, SD-4).
- **Package sources:** point builds at AWS CodeArtifact with upstream repositories and package-origin controls (SD-11).
- **Tenant isolation:** scope client access per project with attribute-based access control (SD-6).
- **Data residency:** use an in-Region model ID instead of a cross-Region inference profile if required (SD-7).
- **Auditing:** turn on S3 server access logging, CloudTrail data events for the bucket and table, and S3 versioning; set removal policies to `RETAIN` (SD-10).
- **Cost and abuse:** add AWS Budgets and CloudWatch alarms on Bedrock tokens, CodeBuild minutes, and trigger invocations (SD-12).
- **Review:** require code owner approval and branch protection on every repository that receives remediation patches (SD-9).

## Accepted security debt

### SD-1: S3 bucket uses the AWS managed KMS key

**Severity:** Medium · **Status:** Accepted · **File:** `infra/remediation_stack.py` (`ArtifactBucket`)

**Description:** The bucket uses SSE-KMS with the AWS managed key `aws/s3` (`BucketEncryption.KMS_MANAGED`) instead of a customer managed key.

**Rationale:** Objects are short-lived (14 to 90 days) and access is controlled by IAM and the bucket policy. The AWS managed key avoids key-policy management for a sample deployment.

**Recommendation:** For compliance requirements or cross-account access, create a customer managed key, set `encryption=s3.BucketEncryption.KMS` with `encryption_key=<key>`, and grant `kms:Decrypt`/`kms:GenerateDataKey` to the agent, build, trigger, and client roles.

### SD-2: Other data stores use AWS owned or default encryption

**Severity:** Low · **Status:** Accepted · **File:** `infra/remediation_stack.py` (`RemediationRuns`, `BuildLogs`, `TriggerLogs`, `CompletionTopic`, `FixMemory`)

**Description:** The DynamoDB table uses the AWS owned key. The log groups have no KMS key. The SNS topic has no KMS key (TLS is enforced). AgentCore Memory uses the service-managed key. The dead-letter queue uses SQS-managed encryption.

**Data stored:** run metadata (project name, status, package names and versions, counts, S3 URIs); build logs (dependency installation and test output); completion emails and events (the same run metadata); memory records (short summaries of library upgrade steps).

**Rationale:** None of these stores holds credentials. Build logs can contain fragments of test output, which is why they expire after 30 days.

**Recommendation:** Pass a customer managed key: `encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED`, `encryption_key` on the log groups, `master_key` on the topic, and `encryption_key_arn` on `CfnMemory`.

### SD-3: Agent runtime uses PUBLIC network mode

**Severity:** Medium · **Status:** Documented · **File:** `infra/remediation_stack.py` (`AgentRuntime`)

**Description:** The runtime has outbound internet access to reach Amazon Bedrock, OSV, and the package registries.

**Mitigations:** The runtime has no inbound endpoint; invocations require IAM authentication. Outbound HTTP from agent code is limited to four HTTPS hosts with redirect checks.

**Recommendation:** Use `network_mode="VPC"` with private subnets, VPC endpoints for AWS services, and an egress proxy or AWS Network Firewall allowing only the required hosts.

### SD-4: CodeBuild runs untrusted code with internet access

**Severity:** Medium · **Status:** Accepted · **File:** `infra/remediation_stack.py` (`BuildProject`)

**Description:** Building and testing a repository runs its install scripts and tests, which can execute arbitrary code. This is the purpose of the build step and cannot be avoided.

**Mitigations:** Builds never run in the agent runtime. The build role can only read `runs/*`, write `runs/*/output/*`, and write its own logs; it cannot read other requests or results, the table, the model, or any secret. Privileged mode is off. Each build runs in a fresh, ephemeral environment with a 30-minute timeout. Regenerated lockfiles are the only build output used, and only if they are valid UTF-8.

**Recommendation:** Run CodeBuild in a VPC with egress filtering, and use a separate AWS account for the remediation stack if repositories are not trusted.

### SD-5: IAM statements with `*` resources

**Severity:** Low · **Status:** Documented · **File:** `infra/remediation_stack.py` (`AgentRuntimePolicy`, `AgentRuntimeRole`)

**Description:** `ecr:GetAuthorizationToken`, `xray:PutTraceSegments`/`PutTelemetryRecords`/`GetSamplingRules`/`GetSamplingTargets`, and `cloudwatch:PutMetricData` use `*`. `logs:DescribeLogGroups` uses `log-group:*` in the account and Region. `bedrock:InvokeModel` is limited to the configured inference profile in the deployment Region and its one foundation model, with a Region wildcard because a cross-Region profile routes to that model in other Regions. The agent can pull images from the CDK bootstrap container-assets repository, which is shared by every CDK app in the account and Region; ECR permissions are per repository, so they cannot be narrowed to one image.

**Rationale:** These actions do not support resource-level permissions, except for model invocation, which is scoped to one model. `cloudwatch:PutMetricData` is restricted with a `cloudwatch:namespace = bedrock-agentcore` condition. This matches the AgentCore Runtime execution role documented by AWS.

**Recommendation:** For a geographic profile, you can replace the foundation-model Region wildcard with the destination Regions listed on the model card.

### SD-6: No per-project isolation in the client policy

**Severity:** Medium · **Status:** Documented · **File:** `infra/remediation_stack.py` (`ClientPolicy`)

**Description:** Any principal with the client policy can upload under any project prefix and read results (including `fix.patch`, which contains source code) for every project.

**Rationale:** The sample targets a single team. Run IDs are random UUIDs, but they are not a security boundary.

**Recommendation:** Attach per-team policies that scope `requests/<project>/*` and `results/<project>/*`, or use attribute-based access control, for example `arn:aws:s3:::<bucket>/results/${aws:PrincipalTag/project}/*`.

### SD-7: Source code sent to Amazon Bedrock

**Severity:** Medium · **Status:** Documented · **File:** `.env` (`MODEL_ID`, `BASE_MODEL_ID`), `infra/settings.py`

**Description:** The agent sends file contents, build logs, and manifests to the model. By default the model is a geographic cross-Region inference profile for the deployment Region (US, EU, AU, or JP), so requests can be processed in any Region of that geography. In other commercial Regions the default is the global profile, which can route requests to any supported commercial Region worldwide.

**Rationale:** Code analysis is the core function. Amazon Bedrock doesn't use prompts and completions to train AWS models and doesn't distribute them to third parties. Traffic is encrypted in transit. Note that AgentCore Observability traces and CloudWatch logs can contain excerpts of tool inputs and outputs.

**Recommendation:** Set `MODEL_ID` in `.env` to an in-Region model ID if data must stay in one Region, and do not upload repositories that contain secrets. Run a secret scanner before calling `remediate`.

### SD-8: Guardrail filters prompt attacks on input only

**Severity:** Low · **Status:** Accepted · **File:** `infra/remediation_stack.py` (`Guardrail`)

**Description:** The guardrail uses the `PROMPT_ATTACK` filter at HIGH strength for input. Output filtering and content categories are not enabled, because the output is source code and those filters produce false positives on code.

**Mitigations:** Model output can only act through tools, and every tool enforces its own guards. The final output is a patch that a human reviews.

**Recommendation:** Add denied topics or word filters if your organization requires them, and evaluate false positives with your own repositories.

### SD-9: AI-generated changes can be incorrect

**Severity:** Medium · **Status:** Documented

**Description:** The agent can produce a change that passes the tests but is wrong, for example when test coverage is low.

**Mitigations:** A patch is published only after the project's own build and tests pass on exactly the published changes. The agent is instructed not to weaken tests. The report explains every change. The agent cannot merge.

**Recommendation:** Require code owner review for remediation patches, and onboard only projects with meaningful test coverage.

### SD-10: Data deleted on stack deletion; no versioning or access logging

**Severity:** Low · **Status:** Accepted · **File:** `infra/remediation_stack.py`

**Description:** The table and log groups use `RemovalPolicy.DESTROY`. The bucket is retained on `cdk destroy`. S3 versioning and server access logging are off.

**Rationale:** Sample convenience, so that a test deployment can be removed completely. All stored data is transient.

**Recommendation:** Use `RemovalPolicy.RETAIN` for the table too, turn on versioning and server access logging, and turn on CloudTrail data events for the bucket and table.

### SD-11: Packages come from public registries

**Severity:** Medium · **Status:** Documented

**Description:** The agent selects versions from PyPI, npm, and Maven Central, and CodeBuild installs them from those registries.

**Mitigations:** The agent only upgrades packages that are already declared; it never adds new packages. A target version must be published, newer than the current version, and free of known OSV advisories. The build and tests must pass.

**Recommendation:** Route builds through AWS CodeArtifact with package-origin controls, and review dependency changes in the patch like any other change.

### SD-12: No per-caller rate limit

**Severity:** Low · **Status:** Accepted · **File:** `functions/trigger/handler.py`, `cdk.json`

**Description:** Any principal with the client policy can start runs.

**Mitigations:** Trigger reserved concurrency (`max_concurrent_runs`, default 10), archive size limit (`max_archive_mb`, default 200), per-run budgets for build attempts, tool calls, and changed files, and lifecycle expiry.

**Recommendation:** Add AWS Budgets and CloudWatch alarms on Bedrock token usage, CodeBuild build minutes, and trigger invocations.

### SD-13: Lambda functions do not run in a VPC

**Severity:** Low · **Status:** Accepted · **File:** `infra/remediation_stack.py` (`TriggerFunction`)

**Description:** The trigger function runs outside a VPC.

**Rationale:** It calls only AWS service APIs (S3, DynamoDB, AgentCore, SQS) and reaches no private resources. Placing it in a VPC would require NAT or several VPC endpoints for no security gain in this design.

**Recommendation:** If your organization requires all functions in a VPC, deploy it in private subnets with VPC endpoints for S3, DynamoDB, and Amazon Bedrock AgentCore.
