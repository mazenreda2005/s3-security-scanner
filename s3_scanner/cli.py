"""Command-line entry point: python -m s3_scanner"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound

from .checks import SEVERITY_ORDER
from .reports import write_csv, write_html, write_json
from .scanner import S3Scanner

WRITERS = {"html": write_html, "json": write_json, "csv": write_csv}

COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m",
          "LOW": "\033[94m", "INFO": "\033[90m"}
RESET = "\033[0m"


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="s3-scanner",
        description="Audit every S3 bucket in an AWS account for security misconfigurations.",
    )
    p.add_argument("--profile", help="AWS CLI profile to use.")
    p.add_argument("--buckets", nargs="+", help="Only scan these buckets.")
    p.add_argument("--format", nargs="+", choices=WRITERS, default=["html", "json"],
                   help="Report formats to write (default: html json).")
    p.add_argument("--output-dir", default="reports", help="Where to write reports.")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER)[:-1],
                   help="Exit with code 1 if any failure at or above this severity (for CI).")
    p.add_argument("--workers", type=int, default=10, help="Parallel bucket scans.")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")
    use_color = sys.stdout.isatty()

    try:
        session = boto3.Session(profile_name=args.profile)
        result = S3Scanner(session, max_workers=args.workers).scan(only=args.buckets)
    except ProfileNotFound as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except NoCredentialsError:
        print("Error: no AWS credentials found. Run 'aws configure' or pass --profile.",
              file=sys.stderr)
        return 2

    counts = result.count_by_severity()
    print(f"\nAccount {result.account_id}: {len(result.buckets)} buckets, "
          f"score {result.score}/100")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        label = f"{COLORS[sev]}{sev:<9}{RESET}" if use_color else f"{sev:<9}"
        print(f"  {label} {counts[sev]}")

    for f in sorted(result.failed, key=lambda f: -SEVERITY_ORDER[f.severity])[:10]:
        print(f"  - [{f.severity}] {f.bucket}: {f.title}")
    if len(result.failed) > 10:
        print(f"  ...and {len(result.failed) - 10} more in the report.")

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"s3-report-{result.account_id}"
    print()
    for fmt in args.format:
        path = WRITERS[fmt](result, out / f"{stem}.{fmt}")
        print(f"Wrote {path}")

    if args.fail_on:
        worst = result.highest_failed_severity()
        if worst and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[args.fail_on]:
            print(f"\nFailing: found {worst} issues (threshold {args.fail_on}).")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
