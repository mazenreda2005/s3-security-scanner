"""Individual security checks for a single S3 bucket.

Each check returns a Finding. Checks never raise on expected AWS errors
(missing config, access denied); they report them as findings instead,
so one locked-down bucket never stops the whole scan.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Callable

from botocore.exceptions import ClientError

PASS, FAIL, WARN, ERROR = "PASS", "FAIL", "WARN", "ERROR"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "everyone on the internet",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account",
}


@dataclass
class Finding:
    bucket: str
    check_id: str
    title: str
    status: str
    severity: str
    detail: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "Unknown")


def _access_error(bucket: str, check_id: str, title: str, exc: ClientError) -> Finding:
    return Finding(
        bucket, check_id, title, ERROR, "INFO",
        f"Could not evaluate: {_error_code(exc)}",
        "Grant the scanner role read access to this bucket's configuration.",
    )


def check_public_access_block(s3, bucket: str) -> Finding:
    cid, title = "S3-01", "Block Public Access enabled"
    fix = (f"aws s3api put-public-access-block --bucket {bucket} "
           "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
           "BlockPublicPolicy=true,RestrictPublicBuckets=true")
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return Finding(bucket, cid, title, FAIL, "HIGH",
                           "No bucket-level Block Public Access configuration.", fix)
        return _access_error(bucket, cid, title, exc)

    disabled = [k for k, v in cfg.items() if not v]
    if disabled:
        return Finding(bucket, cid, title, FAIL, "HIGH",
                       f"Disabled settings: {', '.join(disabled)}.", fix)
    return Finding(bucket, cid, title, PASS, "HIGH", "All four settings are on.", "")


def _is_wildcard_principal(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        values = aws if isinstance(aws, list) else [aws]
        return "*" in values
    return False


def _policy_looks_public(policy: dict) -> bool:
    """Local fallback: an Allow for Principal '*' with no Condition is public."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return any(
        st.get("Effect") == "Allow"
        and _is_wildcard_principal(st.get("Principal"))
        and not st.get("Condition")
        for st in statements
    )


def check_policy_public(s3, bucket: str) -> Finding:
    cid, title = "S3-02", "Bucket policy is not public"
    fix = ("Remove statements with Principal '*' that lack restrictive conditions, "
           "or enable Block Public Access (BlockPublicPolicy, RestrictPublicBuckets).")
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if _error_code(exc) == "NoSuchBucketPolicy":
            return Finding(bucket, cid, title, PASS, "CRITICAL", "No bucket policy attached.", "")
        return _access_error(bucket, cid, title, exc)

    # Prefer AWS's own evaluation; fall back to local analysis if unavailable.
    try:
        is_public = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"].get("IsPublic")
    except ClientError:
        is_public = None
    if is_public is None:
        is_public = _policy_looks_public(policy)

    if is_public:
        return Finding(bucket, cid, title, FAIL, "CRITICAL",
                       "The bucket policy grants access to the public.", fix)
    return Finding(bucket, cid, title, PASS, "CRITICAL", "Policy is not public.", "")


def check_acl_public(s3, bucket: str) -> Finding:
    cid, title = "S3-03", "Bucket ACL is not public"
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
    except ClientError as exc:
        return _access_error(bucket, cid, title, exc)

    exposed = []
    for grant in acl.get("Grants", []):
        uri = grant.get("Grantee", {}).get("URI")
        if uri in PUBLIC_GRANTEES:
            exposed.append(f"{grant.get('Permission')} to {PUBLIC_GRANTEES[uri]}")

    if exposed:
        return Finding(bucket, cid, title, FAIL, "CRITICAL",
                       "ACL grants " + "; ".join(exposed) + ".",
                       f"aws s3api put-bucket-ownership-controls --bucket {bucket} "
                       "--ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'")
    return Finding(bucket, cid, title, PASS, "CRITICAL", "No public grants in ACL.", "")


def check_encryption(s3, bucket: str) -> Finding:
    cid, title = "S3-04", "Default encryption uses KMS"
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket)[
            "ServerSideEncryptionConfiguration"]["Rules"]
    except ClientError as exc:
        if _error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
            return Finding(bucket, cid, title, FAIL, "HIGH",
                           "No default encryption configured.",
                           "Enable default encryption with SSE-KMS.")
        return _access_error(bucket, cid, title, exc)

    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
    if algo.startswith("aws:kms"):
        return Finding(bucket, cid, title, PASS, "MEDIUM", f"Encrypted with {algo}.", "")
    return Finding(bucket, cid, title, WARN, "LOW",
                   f"Encrypted with {algo} (S3-managed keys). Data is encrypted, "
                   "but you cannot audit or revoke key usage.",
                   "For sensitive data, switch to SSE-KMS with a customer-managed key.")


def check_versioning(s3, bucket: str) -> Finding:
    cid, title = "S3-05", "Versioning enabled"
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket)
    except ClientError as exc:
        return _access_error(bucket, cid, title, exc)

    status = resp.get("Status", "Disabled")
    if status == "Enabled":
        return Finding(bucket, cid, title, PASS, "MEDIUM", "Versioning is on.", "")
    return Finding(bucket, cid, title, FAIL, "MEDIUM",
                   f"Versioning is {status}. Deleted or overwritten objects "
                   "cannot be recovered (ransomware risk).",
                   f"aws s3api put-bucket-versioning --bucket {bucket} "
                   "--versioning-configuration Status=Enabled")


def _denies_insecure_transport(statement: dict) -> bool:
    if statement.get("Effect") != "Deny":
        return False
    value = statement.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
    values = value if isinstance(value, list) else [value]
    return any(str(v).lower() == "false" for v in values)


def check_tls_enforced(s3, bucket: str) -> Finding:
    cid, title = "S3-06", "HTTPS-only access enforced"
    fix = "Add a Deny statement for s3:* when aws:SecureTransport is false."
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if _error_code(exc) == "NoSuchBucketPolicy":
            return Finding(bucket, cid, title, FAIL, "MEDIUM",
                           "No bucket policy, so plain-HTTP requests are allowed.", fix)
        return _access_error(bucket, cid, title, exc)

    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    if any(_denies_insecure_transport(st) for st in statements):
        return Finding(bucket, cid, title, PASS, "MEDIUM", "Policy denies non-TLS requests.", "")
    return Finding(bucket, cid, title, FAIL, "MEDIUM",
                   "Bucket policy does not deny plain-HTTP requests.", fix)


def check_logging(s3, bucket: str) -> Finding:
    cid, title = "S3-07", "Server access logging enabled"
    try:
        resp = s3.get_bucket_logging(Bucket=bucket)
    except ClientError as exc:
        return _access_error(bucket, cid, title, exc)

    target = resp.get("LoggingEnabled", {}).get("TargetBucket")
    if target:
        return Finding(bucket, cid, title, PASS, "LOW", f"Logs delivered to {target}.", "")
    return Finding(bucket, cid, title, FAIL, "LOW",
                   "No access logs. You cannot see who read or changed objects.",
                   "Enable server access logging to a dedicated log bucket, "
                   "or CloudTrail data events for sensitive buckets.")


ALL_CHECKS: list[Callable] = [
    check_public_access_block,
    check_policy_public,
    check_acl_public,
    check_encryption,
    check_versioning,
    check_tls_enforced,
    check_logging,
]
