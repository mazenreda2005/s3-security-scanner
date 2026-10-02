"""Orchestrates checks across all buckets, in parallel and region-aware."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .checks import ALL_CHECKS, ERROR, FAIL, PASS, SEVERITY_ORDER, Finding

log = logging.getLogger(__name__)

BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

# Weight per severity when computing the 0-100 score.
SCORE_WEIGHTS = {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1, "INFO": 0}


@dataclass
class AccountPublicAccess:
    all_enabled: bool
    detail: str


@dataclass
class ScanResult:
    account_id: str
    scanned_at: str
    findings: list[Finding] = field(default_factory=list)
    buckets: list[str] = field(default_factory=list)
    account_pab: AccountPublicAccess | None = None

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FAIL]

    def count_by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.failed:
            counts[f.severity] += 1
        return counts

    @property
    def score(self) -> int:
        """Weighted pass rate across scored checks: 100 means everything passed."""
        scored = [f for f in self.findings if f.status in (PASS, FAIL)]
        total = sum(SCORE_WEIGHTS[f.severity] for f in scored)
        if total == 0:
            return 100
        passed = sum(SCORE_WEIGHTS[f.severity] for f in scored if f.status == PASS)
        return round(100 * passed / total)

    def highest_failed_severity(self) -> str | None:
        if not self.failed:
            return None
        return max(self.failed, key=lambda f: SEVERITY_ORDER[f.severity]).severity


class S3Scanner:
    def __init__(self, session: boto3.Session | None = None, max_workers: int = 10):
        self.session = session or boto3.Session()
        self.max_workers = max_workers
        self._clients: dict[str, object] = {}

    def _client(self, region: str):
        if region not in self._clients:
            self._clients[region] = self.session.client(
                "s3", region_name=region, config=BOTO_CONFIG)
        return self._clients[region]

    def _bucket_region(self, bucket: str) -> str:
        try:
            loc = self._client("us-east-1").get_bucket_location(Bucket=bucket)
        except ClientError:
            return "us-east-1"
        # us-east-1 returns None; old eu-west-1 buckets return "EU".
        region = loc.get("LocationConstraint") or "us-east-1"
        return "eu-west-1" if region == "EU" else region

    def account_id(self) -> str:
        try:
            return self.session.client("sts").get_caller_identity()["Account"]
        except (ClientError, BotoCoreError):
            return "unknown"

    def check_account_public_access(self, account_id: str) -> AccountPublicAccess:
        control = self.session.client("s3control", region_name="us-east-1")
        try:
            cfg = control.get_public_access_block(AccountId=account_id)[
                "PublicAccessBlockConfiguration"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                return AccountPublicAccess(False, "Not configured at the account level.")
            return AccountPublicAccess(False, f"Could not read ({code}).")
        except BotoCoreError as exc:
            return AccountPublicAccess(False, f"Could not read ({exc.__class__.__name__}).")

        off = [k for k, v in cfg.items() if not v]
        if off:
            return AccountPublicAccess(False, f"Disabled at account level: {', '.join(off)}.")
        return AccountPublicAccess(True, "All four settings are enabled account-wide.")

    def list_buckets(self) -> list[str]:
        resp = self._client("us-east-1").list_buckets()
        return sorted(b["Name"] for b in resp.get("Buckets", []))

    def scan_bucket(self, bucket: str) -> list[Finding]:
        s3 = self._client(self._bucket_region(bucket))
        findings = []
        for check in ALL_CHECKS:
            try:
                findings.append(check(s3, bucket))
            except Exception as exc:  # noqa: BLE001 - never let one check kill the scan
                log.exception("Check %s failed on %s", check.__name__, bucket)
                findings.append(Finding(bucket, check.__name__, check.__name__, ERROR,
                                        "INFO", f"Unexpected error: {exc}", ""))
        return findings

    def scan(self, only: list[str] | None = None) -> ScanResult:
        account = self.account_id()
        result = ScanResult(
            account_id=account,
            scanned_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )
        result.account_pab = self.check_account_public_access(account)

        buckets = self.list_buckets()
        if only:
            wanted = set(only)
            buckets = [b for b in buckets if b in wanted]
        result.buckets = buckets
        log.info("Scanning %d bucket(s)", len(buckets))

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.scan_bucket, b): b for b in buckets}
            for fut in as_completed(futures):
                result.findings.extend(fut.result())

        result.findings.sort(key=lambda f: (f.bucket, f.check_id))
        return result
