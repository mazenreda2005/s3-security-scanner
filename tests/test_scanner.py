import json

import boto3
import pytest
from moto import mock_aws

from s3_scanner.checks import FAIL, PASS, WARN
from s3_scanner.cli import main
from s3_scanner.scanner import S3Scanner

REGION = "us-east-1"


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        yield boto3.client("s3", region_name=REGION)


def make_secure_bucket(s3, name):
    s3.create_bucket(Bucket=name)
    s3.create_bucket(Bucket=f"{name}-logs", ACL="log-delivery-write")
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }))
    s3.put_bucket_logging(Bucket=name, BucketLoggingStatus={
        "LoggingEnabled": {"TargetBucket": f"{name}-logs", "TargetPrefix": "logs/"}})


def by_check(findings, bucket):
    return {f.check_id: f for f in findings if f.bucket == bucket}


def test_secure_bucket_passes(aws):
    make_secure_bucket(aws, "good-bucket")
    result = S3Scanner(boto3.Session()).scan(only=["good-bucket"])
    checks = by_check(result.findings, "good-bucket")
    assert all(f.status == PASS for f in checks.values()), checks
    assert result.score == 100


def test_insecure_bucket_fails(aws):
    aws.create_bucket(Bucket="bad-bucket")
    aws.put_bucket_policy(Bucket="bad-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::bad-bucket/*"}],
    }))
    result = S3Scanner(boto3.Session()).scan(only=["bad-bucket"])
    checks = by_check(result.findings, "bad-bucket")

    assert checks["S3-01"].status == FAIL          # no block public access
    assert checks["S3-02"].status == FAIL          # public policy
    assert checks["S3-02"].severity == "CRITICAL"
    assert checks["S3-05"].status == FAIL          # no versioning
    assert checks["S3-06"].status == FAIL          # no TLS enforcement
    assert checks["S3-07"].status == FAIL          # no logging
    assert result.highest_failed_severity() == "CRITICAL"
    assert result.score < 50


def test_public_acl_detected(aws):
    aws.create_bucket(Bucket="acl-bucket")
    aws.put_bucket_acl(Bucket="acl-bucket", ACL="public-read")
    result = S3Scanner(boto3.Session()).scan(only=["acl-bucket"])
    assert by_check(result.findings, "acl-bucket")["S3-03"].status == FAIL


def test_sse_s3_is_warning_not_failure(aws):
    aws.create_bucket(Bucket="sse-bucket")
    aws.put_bucket_encryption(Bucket="sse-bucket", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    result = S3Scanner(boto3.Session()).scan(only=["sse-bucket"])
    assert by_check(result.findings, "sse-bucket")["S3-04"].status == WARN


def test_bucket_in_other_region(aws):
    eu = boto3.client("s3", region_name="eu-west-1")
    eu.create_bucket(Bucket="eu-bucket",
                     CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    result = S3Scanner(boto3.Session()).scan(only=["eu-bucket"])
    assert len(by_check(result.findings, "eu-bucket")) == 7


def test_cli_writes_reports_and_fails_on_critical(aws, tmp_path):
    aws.create_bucket(Bucket="cli-bucket")
    aws.put_bucket_acl(Bucket="cli-bucket", ACL="public-read")
    code = main(["--output-dir", str(tmp_path), "--format", "html", "json", "csv",
                 "--fail-on", "CRITICAL"])
    assert code == 1
    files = {p.suffix for p in tmp_path.iterdir()}
    assert files == {".html", ".json", ".csv"}
    data = json.loads(next(tmp_path.glob("*.json")).read_text())
    assert data["summary"]["CRITICAL"] >= 1


def test_policy_with_condition_is_not_flagged_locally():
    from s3_scanner.checks import _policy_looks_public
    restricted = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                 "Resource": "*",
                                 "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}
    open_ = {"Statement": {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "s3:*",
                           "Resource": "*"}}
    assert not _policy_looks_public(restricted)
    assert _policy_looks_public(open_)
