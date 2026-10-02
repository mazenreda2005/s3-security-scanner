"""Write scan results as JSON, CSV, or a self-contained HTML report."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from html import escape
from pathlib import Path

from .checks import FAIL, PASS, SEVERITY_ORDER, WARN
from .scanner import ScanResult

SEVERITY_COLORS = {
    "CRITICAL": "#B3261E",
    "HIGH": "#C8620A",
    "MEDIUM": "#A8820F",
    "LOW": "#3A6EA5",
    "INFO": "#6B7785",
}


def write_json(result: ScanResult, path: Path) -> Path:
    payload = {
        "account_id": result.account_id,
        "scanned_at": result.scanned_at,
        "score": result.score,
        "account_public_access_block": {
            "all_enabled": result.account_pab.all_enabled if result.account_pab else None,
            "detail": result.account_pab.detail if result.account_pab else None,
        },
        "summary": result.count_by_severity(),
        "buckets_scanned": len(result.buckets),
        "findings": [f.to_dict() for f in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_csv(result: ScanResult, path: Path) -> Path:
    fields = ["bucket", "check_id", "title", "status", "severity", "detail", "remediation"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for f in result.findings:
            writer.writerow(f.to_dict())
    return path


def _score_color(score: int) -> str:
    if score >= 90:
        return "#2E7D4F"
    if score >= 70:
        return "#A8820F"
    return "#B3261E"


def _bucket_rows(result: ScanResult) -> str:
    by_bucket = defaultdict(list)
    for f in result.findings:
        by_bucket[f.bucket].append(f)

    def risk(bucket: str) -> tuple:
        sev = [SEVERITY_ORDER[f.severity] for f in by_bucket.get(bucket, []) if f.status == FAIL]
        return (-max(sev, default=-1), -len(sev), bucket)

    rows = []
    for bucket in sorted(result.buckets, key=risk):
        findings = by_bucket.get(bucket, [])
        failed = sorted((f for f in findings if f.status in (FAIL, WARN)),
                        key=lambda f: -SEVERITY_ORDER[f.severity])
        passed = sum(1 for f in findings if f.status == PASS)
        worst = failed[0].severity if failed and failed[0].status == FAIL else None

        badge = (f'<span class="sev" style="--c:{SEVERITY_COLORS[worst]}">{worst.title()}</span>'
                 if worst else '<span class="ok">No failures</span>')

        items = []
        for f in failed:
            fix = (f'<pre class="fix">{escape(f.remediation)}</pre>' if f.remediation else "")
            items.append(
                f'<li><span class="sev" style="--c:{SEVERITY_COLORS[f.severity]}">'
                f'{f.severity.title()}</span>'
                f'<div><strong>{escape(f.title)}</strong>'
                f'{" (warning)" if f.status == WARN else ""}'
                f'<p>{escape(f.detail)}</p>{fix}</div></li>'
            )
        body = (f'<ul class="findings">{"".join(items)}</ul>' if items
                else '<p class="clean">Every check passed for this bucket.</p>')

        rows.append(
            f'<details{" open" if worst in ("CRITICAL", "HIGH") else ""}>'
            f'<summary><code>{escape(bucket)}</code>'
            f'<span class="meta">{passed}/{len(findings)} checks passed</span>{badge}</summary>'
            f'{body}</details>'
        )
    return "\n".join(rows) or '<p class="clean">No buckets found in this account.</p>'


def write_html(result: ScanResult, path: Path) -> Path:
    counts = result.count_by_severity()
    total_failed = sum(counts.values())
    score = result.score

    segments = "".join(
        f'<span style="flex:{counts[s]};background:{SEVERITY_COLORS[s]}" '
        f'title="{s.title()}: {counts[s]}"></span>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]
    ) or '<span style="flex:1;background:#2E7D4F" title="No failures"></span>'

    legend = "".join(
        f'<li><i style="background:{SEVERITY_COLORS[s]}"></i>{s.title()} <b>{counts[s]}</b></li>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    pab = result.account_pab
    pab_html = ""
    if pab:
        cls = "pab ok-box" if pab.all_enabled else "pab warn-box"
        pab_html = (f'<p class="{cls}"><strong>Account-level Block Public Access:</strong> '
                    f'{escape(pab.detail)}</p>')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>S3 security report, account {escape(result.account_id)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{
    --ink: #13263B; --steel: #5B6B7C; --paper: #FBFCFD; --rule: #DCE2E8; --wash: #EEF2F6;
    --sans: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
    --mono: "IBM Plex Mono", ui-monospace, Consolas, monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--paper); color: var(--ink); font: 16px/1.55 var(--sans); }}
  main {{ max-width: 960px; margin: 0 auto; padding: 48px 24px 80px; }}
  header {{ display: grid; grid-template-columns: 1fr auto; gap: 24px; align-items: end;
           border-bottom: 2px solid var(--ink); padding-bottom: 24px; }}
  h1 {{ font-size: 28px; line-height: 1.2; margin: 0 0 6px; }}
  header p {{ margin: 0; color: var(--steel); }}
  .score {{ text-align: right; }}
  .score b {{ display: block; font-size: 88px; line-height: .9; font-weight: 700;
              color: {_score_color(score)}; letter-spacing: -2px; }}
  .score span {{ color: var(--steel); font-size: 14px; }}
  .bar {{ display: flex; height: 14px; margin: 32px 0 12px; border-radius: 2px; overflow: hidden; gap: 2px; }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 20px; list-style: none; padding: 0; margin: 0 0 8px;
             color: var(--steel); font-size: 14px; }}
  .legend i {{ display: inline-block; width: 10px; height: 10px; margin-right: 6px; border-radius: 2px; }}
  .legend b {{ color: var(--ink); margin-left: 4px; }}
  .pab {{ padding: 12px 16px; border-left: 4px solid; margin: 24px 0; background: var(--wash); }}
  .ok-box {{ border-color: #2E7D4F; }} .warn-box {{ border-color: #B3261E; }}
  h2 {{ font-size: 20px; margin: 40px 0 12px; }}
  details {{ border-top: 1px solid var(--rule); }}
  details:last-of-type {{ border-bottom: 1px solid var(--rule); }}
  summary {{ display: grid; grid-template-columns: 1fr auto auto; gap: 16px; align-items: center;
             padding: 14px 4px; cursor: pointer; list-style: none; }}
  summary::-webkit-details-marker {{ display: none; }}
  summary:focus-visible {{ outline: 2px solid var(--ink); outline-offset: 2px; }}
  summary code {{ font: 500 15px var(--mono); overflow-wrap: anywhere; }}
  .meta {{ color: var(--steel); font-size: 14px; }}
  .sev {{ font-size: 13px; font-weight: 600; color: var(--c); border: 1.5px solid var(--c);
          padding: 1px 8px; border-radius: 3px; white-space: nowrap; }}
  .ok {{ font-size: 13px; color: #2E7D4F; font-weight: 600; }}
  .findings {{ list-style: none; padding: 0 4px 16px; margin: 0; }}
  .findings li {{ display: grid; grid-template-columns: 84px 1fr; gap: 12px; padding: 10px 0; }}
  .findings li .sev {{ justify-self: start; align-self: start; }}
  .findings p {{ margin: 2px 0 6px; color: var(--steel); max-width: 70ch; }}
  .fix {{ font: 13px/1.5 var(--mono); background: var(--wash); padding: 10px 12px; margin: 0;
          white-space: pre-wrap; overflow-wrap: anywhere; border-radius: 3px; }}
  .clean {{ color: var(--steel); padding: 0 4px 16px; margin: 0; }}
  footer {{ margin-top: 48px; color: var(--steel); font-size: 13px; }}
  @media (max-width: 640px) {{
    header {{ grid-template-columns: 1fr; }} .score {{ text-align: left; }}
    summary {{ grid-template-columns: 1fr auto; }} .meta {{ display: none; }}
    .findings li {{ grid-template-columns: 1fr; gap: 4px; }}
  }}
  @media print {{ details {{ break-inside: avoid; }} details:not([open]) > *:not(summary) {{ display: block; }} }}
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>S3 security report</h1>
      <p>AWS account {escape(result.account_id)}, scanned {escape(result.scanned_at)}</p>
      <p>{len(result.buckets)} buckets, {total_failed} failed checks</p>
    </div>
    <div class="score"><b>{score}</b><span>Security score out of 100</span></div>
  </header>

  <div class="bar" role="img" aria-label="Failed checks by severity">{segments}</div>
  <ul class="legend">{legend}</ul>
  {pab_html}

  <h2>Buckets</h2>
  {_bucket_rows(result)}

  <footer>Generated by s3-security-scanner. Score weights: critical 10, high 6, medium 3, low 1.</footer>
</main>
</body>
</html>"""
    path.write_text(html, encoding="utf-8")
    return path
