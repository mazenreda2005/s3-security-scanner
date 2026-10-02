"""Generate docs/sample-report.html against a mocked AWS account (no real AWS needed)."""
import json
import os
from pathlib import Path

import boto3
from moto import mock_aws

from s3_scanner.reports import write_html
from s3_scanner.scanner import S3Scanner

os.environ.update(AWS_ACCESS_KEY_ID="demo", AWS_SECRET_ACCESS_KEY="demo",
                  AWS_DEFAULT_REGION="us-east-1")

with mock_aws():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="acme-marketing-assets")
    s3.put_bucket_acl(Bucket="acme-marketing-assets", ACL="public-read")

    s3.create_bucket(Bucket="acme-customer-exports")
    s3.put_bucket_policy(Bucket="acme-customer-exports", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                       "Resource": "arn:aws:s3:::acme-customer-exports/*"}]}))

    s3.create_bucket(Bucket="acme-app-logs", ACL="log-delivery-write")
    s3.put_bucket_encryption(Bucket="acme-app-logs", ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
    s3.put_public_access_block(Bucket="acme-app-logs", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    s3.create_bucket(Bucket="acme-prod-backups")
    for call, kw in [
        (s3.put_public_access_block, {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}),
        (s3.put_bucket_encryption, {"ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}),
        (s3.put_bucket_versioning, {"VersioningConfiguration": {"Status": "Enabled"}}),
        (s3.put_bucket_logging, {"BucketLoggingStatus": {"LoggingEnabled": {
            "TargetBucket": "acme-app-logs", "TargetPrefix": "backups/"}}}),
        (s3.put_bucket_policy, {"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": ["arn:aws:s3:::acme-prod-backups", "arn:aws:s3:::acme-prod-backups/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})}),
    ]:
        call(Bucket="acme-prod-backups", **kw)

    result = S3Scanner(boto3.Session()).scan()
    out = write_html(result, Path(__file__).parent / "sample-report.html")
    print(f"Wrote {out} (score {result.score})")
