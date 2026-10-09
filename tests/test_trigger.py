# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import handler


def s3_event(key: str, size: int = 1000, bucket: str = "artifacts"):
    return {"detail": {"bucket": {"name": bucket}, "object": {"key": key, "size": size}}}


def test_parse_valid_request(monkeypatch):
    monkeypatch.setenv("ARTIFACT_BUCKET", "artifacts")
    key = "requests/orders-api/3f2c1c8e-1111-4a4a-9999-123456789abc/source.zip"
    assert handler.parse_event(s3_event(key)) == ("artifacts", key, 1000)


def test_ignores_other_keys_and_buckets(monkeypatch):
    monkeypatch.setenv("ARTIFACT_BUCKET", "artifacts")
    assert handler.parse_event(s3_event("results/x/3f2c1c8e-1111/result.json")) is None
    assert handler.parse_event(s3_event("requests/../etc/3f2c1c8e-1111/source.zip")) is None
    assert handler.parse_event(s3_event("requests/a/3f2c1c8e-1111/source.exe")) is None
    assert handler.parse_event(s3_event("requests/a/3f2c1c8e-1111/source.zip", bucket="other")) is None


def test_options_from_metadata():
    options = handler.options_from_metadata({"ecosystem": "python", "app-dir": "svc", "packages": "jinja2, requests", "ignore": ""})
    assert options == {"ecosystem": "python", "app_dir": "svc", "packages": ["jinja2", "requests"]}


def test_rejects_large_archive(monkeypatch):
    monkeypatch.setenv("ARTIFACT_BUCKET", "artifacts")
    monkeypatch.setenv("MAX_ARCHIVE_MB", "1")
    event = s3_event("requests/a/3f2c1c8e-1111-4a4a/source.zip", size=5 * 1024 * 1024)
    assert handler.handler(event, None) == {"started": False, "reason": "archive too large"}
