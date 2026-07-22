"""
vision-M: Report Delivery E2E Tests
====================================
End-to-end test of report generation and file delivery.
Verifies CRITICAL and LOW reports, HTML and Markdown formats,
all required sections present. Prints HTML sample. Exit 0 on success.
"""

import sys, os, shutil, tempfile
from datetime import datetime, timezone

sys.path.insert(0, '/data/workspace/vision-M')

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ PASS  {name}")
    else:
        FAIL += 1
        print(f"  ❌ FAIL  {name}" + (f" — {detail}" if detail else ""))


# ═══════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════

def generate_report(result: dict, fmt: str = "html",
                    output_dir: str = None) -> str:
    """Generate a vision-M security scan report.

    Args:
        result: SecurityWorker result dict (findings, risk_level, etc.)
        fmt: 'html' or 'markdown'
        output_dir: directory to write the report file

    Returns:
        Absolute path to the generated report file.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="vision_m_report_")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S-%f")[:23]  # truncate to ms
    risk_level = result.get("risk_level", "UNKNOWN")
    summary = result.get("summary", "No summary")
    findings = result.get("findings", [])
    confidence = result.get("confidence", 0.0)
    subtasks = result.get("completed_subtasks", [])
    requests = result.get("requests_consumed", 0)

    # Colour mappings
    if risk_level == "CRITICAL":
        risk_color = "#d32f2f"
        risk_badge = "🔴 CRITICAL"
    elif risk_level == "HIGH":
        risk_color = "#f57c00"
        risk_badge = "🟠 HIGH"
    elif risk_level == "MEDIUM":
        risk_color = "#fbc02d"
        risk_badge = "🟡 MEDIUM"
    elif risk_level == "LOW":
        risk_color = "#388e3c"
        risk_badge = "🟢 LOW"
    else:
        risk_color = "#757575"
        risk_badge = "⚪ UNKNOWN"

    # Executive summary text
    if risk_level == "LOW":
        exec_summary = (
            "The scan found no significant security issues. The target appears "
            "to be free of exposed sensitive data. No immediate action is required."
        )
        remediation = [
            "Continue monitoring the target for changes.",
            "Maintain existing security controls.",
            "Schedule a follow-up scan in 30 days.",
        ]
    else:
        exec_summary = (
            f"The scan detected {risk_level} severity security findings. "
            f"Immediate attention is recommended. {len(findings)} finding(s) "
            f"were identified with {confidence:.0%} confidence."
        )
        remediation = [
            "Immediately rotate any exposed credentials.",
            "Remove PII from public-facing pages.",
            "Implement a Web Application Firewall (WAF).",
            "Conduct a full penetration test.",
            "Review access controls and authorization policies.",
        ]

    if fmt == "html":
        content = _generate_html(timestamp, risk_level, risk_color,
                                 risk_badge, summary, exec_summary,
                                 findings, confidence, subtasks,
                                 requests, remediation)
        ext = ".html"
    else:
        content = _generate_markdown(timestamp, risk_level, risk_badge,
                                     summary, exec_summary, findings,
                                     confidence, subtasks, requests,
                                     remediation)
        ext = ".md"

    os.makedirs(output_dir, exist_ok=True)
    filename = f"vision_m_scan_{timestamp.replace(':', '-')}{ext}"
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w") as f:
        f.write(content)

    return os.path.abspath(filepath)


def _generate_html(timestamp, risk_level, risk_color, risk_badge,
                   summary, exec_summary, findings, confidence,
                   subtasks, requests, remediation):
    findings_rows = ""
    for i, f in enumerate(findings):
        findings_rows += f"""
        <tr>
            <td>{i + 1}</td>
            <td>{f.get('title', 'N/A')}</td>
            <td>{f.get('severity', 'N/A')}</td>
            <td>{f.get('risk_level', 'N/A')}</td>
            <td>{f.get('confidence', 'N/A')}</td>
            <td>{f.get('findings_count', 0)}</td>
        </tr>"""

    remediation_items = "\n".join(
        f"            <li>{r}</li>" for r in remediation
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>vision-M Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 0; padding: 20px; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #fff; border-radius: 8px;
                      box-shadow: 0 2px 12px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #1a237e, #283593);
                   color: #fff; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; font-weight: 700; }}
        .header .subtitle {{ font-size: 14px; opacity: 0.85; margin-top: 6px; }}
        .risk-badge {{ display: inline-block; padding: 8px 24px; border-radius: 20px;
                       font-weight: 700; font-size: 18px; margin-top: 12px;
                       background: {risk_color}; color: #fff; }}
        .section {{ padding: 24px 30px; border-bottom: 1px solid #e0e0e0; }}
        .section:last-child {{ border-bottom: none; }}
        .section h2 {{ color: #1a237e; font-size: 20px; margin-top: 0;
                       border-bottom: 2px solid #e8eaf6; padding-bottom: 8px; }}
        .section h3 {{ color: #283593; font-size: 16px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e0e0e0; }}
        th {{ background: #e8eaf6; color: #1a237e; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .metadata-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        .metadata-item {{ padding: 8px; background: #f9f9f9; border-radius: 4px; }}
        .metadata-item strong {{ color: #1a237e; }}
        .footer {{ background: #1a237e; color: #fff; text-align: center; padding: 16px;
                   font-size: 12px; }}
        .remediation ul {{ margin: 0; padding-left: 20px; }}
        .remediation li {{ margin-bottom: 6px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 vision-M Security Scan Report</h1>
            <div class="subtitle">Automated Security Assessment</div>
            <div class="risk-badge">{risk_badge}</div>
        </div>

        <div class="section">
            <h2>📋 Executive Summary</h2>
            <p>{exec_summary}</p>
            <p><strong>Overall Summary:</strong> {summary}</p>
        </div>

        <div class="section">
            <h2>📊 Risk Score / Level</h2>
            <div class="metadata-grid">
                <div class="metadata-item"><strong>Risk Level:</strong> {risk_level}</div>
                <div class="metadata-item"><strong>Confidence:</strong> {confidence:.1%}</div>
                <div class="metadata-item"><strong>Findings Count:</strong> {len(findings)}</div>
                <div class="metadata-item"><strong>Subtasks Completed:</strong> {len(subtasks)}</div>
            </div>
        </div>

        <div class="section">
            <h2>🔎 Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Risk Level</th>
                        <th>Confidence</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>{findings_rows}
                </tbody>
            </table>
        </div>

        <div class="section remediation">
            <h2>🛡 Remediation Recommendations</h2>
            <ul>
{remediation_items}
            </ul>
        </div>

        <div class="section">
            <h2>📋 Scan Metadata</h2>
            <div class="metadata-grid">
                <div class="metadata-item"><strong>Scan ID:</strong> VISION-M-{timestamp}</div>
                <div class="metadata-item"><strong>Timestamp:</strong> {timestamp}</div>
                <div class="metadata-item"><strong>Format:</strong> HTML</div>
                <div class="metadata-item"><strong>Requests Used:</strong> {requests}</div>
                <div class="metadata-item"><strong>Confidence:</strong> {confidence:.1%}</div>
                <div class="metadata-item"><strong>Engine:</strong> SecurityWorker</div>
                <div class="metadata-item"><strong>Subtasks:</strong> {', '.join(subtasks)}</div>
                <div class="metadata-item"><strong>Generator:</strong> vision-M Report Engine v1.0</div>
            </div>
        </div>

        <div class="footer">
            vision-M Security Scanner — Confidential Report —
            Generated {timestamp} — © vision-M Project
        </div>
    </div>
</body>
</html>"""


def _generate_markdown(timestamp, risk_level, risk_badge, summary,
                       exec_summary, findings, confidence, subtasks,
                       requests, remediation):
    findings_table = "| # | Title | Severity | Risk Level | Confidence | Count |\n"
    findings_table += "|---|-------|----------|------------|------------|-------|\n"
    for i, f in enumerate(findings):
        findings_table += (
            f"| {i + 1} | {f.get('title', 'N/A')} "
            f"| {f.get('severity', 'N/A')} "
            f"| {f.get('risk_level', 'N/A')} "
            f"| {f.get('confidence', 'N/A')} "
            f"| {f.get('findings_count', 0)} |\n"
        )

    remediation_list = "\n".join(f"- {r}" for r in remediation)

    return f"""# vision-M Security Scan Report

**{risk_badge}** — Automated Security Assessment

---

## Executive Summary

{exec_summary}

**Overall Summary:** {summary}

---

## Risk Score / Level

- **Risk Level:** {risk_level}
- **Confidence:** {confidence:.1%}
- **Findings Count:** {len(findings)}
- **Subtasks Completed:** {len(subtasks)}

---

## Findings

{findings_table}

---

## Remediation Recommendations

{remediation_list}

---

## Scan Metadata

- **Scan ID:** VISION-M-{timestamp}
- **Timestamp:** {timestamp}
- **Format:** Markdown
- **Requests Used:** {requests}
- **Confidence:** {confidence:.1%}
- **Engine:** SecurityWorker
- **Subtasks:** {', '.join(subtasks)}
- **Generator:** vision-M Report Engine v1.0

---

*vision-M Security Scanner — Confidential Report — Generated {timestamp} — © vision-M Project*
"""


# ═══════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════

from layer1_orchestration.execution.job_contract import (
    JobRecord, JobContract, JobState,
)
from layer1_orchestration.execution.job_store import JobStore
from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
from layer1_orchestration.execution.job_queue import JobQueue
from layer1_orchestration.execution.real_workers import SecurityWorker


# ═══════════════════════════════════════════════════════════════════
# TEST 1: CRITICAL Report — HTML Format
# ═══════════════════════════════════════════════════════════════════
print("=" * 60)
print("TEST 1: CRITICAL Report — HTML Format")
print("=" * 60)

STORE_DIR = "/tmp/vision_m_report_e2e"
if os.path.exists(STORE_DIR):
    shutil.rmtree(STORE_DIR)
os.makedirs(STORE_DIR)

store = JobStore(STORE_DIR)
mgr = JobLifecycleManager()
queue = JobQueue(store, mgr)

CRITICAL_HTML_CONTENT = (
    "<html><body>"
    "admin@corp.com | api_key=sk-live-abc123 | password=secret! | 192.168.1.100"
    "</body></html>"
)

contract = JobContract.create(
    tenant_id='report-crit', mission_id='RPT-CRIT-001',
    parent_finding_id='f-crit', parent_chain_id='c-crit',
    hypothesis_id='h-crit',
    source_engine='security', target_engine='security',
    target_asset='https://vulnerable.corp.com',
    normalized_asset='vulnerable.corp.com',
    action_type='security_scan',
    request_budget=10,
    authorization_reference='AUTH-RPT-CRIT-001',
)
record = JobRecord(contract=contract)
record = queue.enqueue(record)

worker = SecurityWorker('sec-report-crit', queue, store, mgr)
record = queue.assign(record, worker.worker_id)
record = queue.start_execution(record, worker.worker_id)
result_crit = worker._do_work(
    record,
    {'content': CRITICAL_HTML_CONTENT, 'html': CRITICAL_HTML_CONTENT},
)

check("CRITICAL risk_level", result_crit.get('risk_level') == 'CRITICAL',
      f"Got {result_crit.get('risk_level')}")
check("6 subtasks completed", len(result_crit['completed_subtasks']) == 6)
check("findings present", len(result_crit.get('findings', [])) > 0)

# Generate HTML report
report_dir = tempfile.mkdtemp(prefix="vision_m_reports_")
report_path_html = generate_report(result_crit, fmt="html", output_dir=report_dir)
check("report_path returned",
      isinstance(report_path_html, str) and len(report_path_html) > 0)
check("report file exists on disk", os.path.exists(report_path_html))
check("report has .html extension", report_path_html.endswith(".html"))

# Read and verify report content
with open(report_path_html, 'r') as f:
    report_content = f.read()

check("vision-M header present",
      "vision-M Security Scan Report" in report_content)
check("Executive Summary present",
      "Executive Summary" in report_content)
check("Risk Score/Level present",
      "Risk Score" in report_content or "Risk Level" in report_content)
check("Findings section present",
      "Findings" in report_content)
check("Remediation Recommendations present",
      "Remediation" in report_content)
check("Scan Metadata present",
      "Scan Metadata" in report_content)
check("Footer present",
      "Confidential Report" in report_content)
check("CRITICAL language in report",
      "CRITICAL" in report_content)
check("CRITICAL risk colour (red) in HTML",
      '#d32f2f' in report_content or '🔴' in report_content)

print(f"\n  Report path: {report_path_html}")
print(f"  Report size: {len(report_content)} bytes")


# ═══════════════════════════════════════════════════════════════════
# TEST 2: LOW Report — HTML Format
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 2: LOW Report — HTML Format")
print("=" * 60)

STORE_DIR2 = "/tmp/vision_m_report_low"
if os.path.exists(STORE_DIR2):
    shutil.rmtree(STORE_DIR2)
os.makedirs(STORE_DIR2)

store2 = JobStore(STORE_DIR2)
mgr2 = JobLifecycleManager()
queue2 = JobQueue(store2, mgr2)

SAFE_HTML_CONTENT = (
    "<html><body><h1>Public Page</h1><p>No sensitive data.</p></body></html>"
)

contract2 = JobContract.create(
    tenant_id='report-low', mission_id='RPT-LOW-001',
    parent_finding_id='f-low', parent_chain_id='c-low',
    hypothesis_id='h-low',
    source_engine='security', target_engine='security',
    target_asset='https://safe.example.com',
    normalized_asset='safe.example.com',
    action_type='security_scan',
    request_budget=10,
    authorization_reference='AUTH-RPT-LOW-001',
)
record2 = JobRecord(contract=contract2)
record2 = queue2.enqueue(record2)

worker2 = SecurityWorker('sec-report-low', queue2, store2, mgr2)
record2 = queue2.assign(record2, worker2.worker_id)
record2 = queue2.start_execution(record2, worker2.worker_id)
result_low = worker2._do_work(
    record2,
    {'content': SAFE_HTML_CONTENT, 'html': SAFE_HTML_CONTENT},
)

check("LOW risk_level", result_low.get('risk_level') == 'LOW',
      f"Got {result_low.get('risk_level')}")
check("No alert_sent", 'alert_sent' not in result_low)

# Generate LOW HTML report
report_dir2 = tempfile.mkdtemp(prefix="vision_m_reports_low_")
report_path_low_html = generate_report(
    result_low, fmt="html", output_dir=report_dir2
)
check("LOW report exists", os.path.exists(report_path_low_html))

with open(report_path_low_html, 'r') as f:
    low_report_content = f.read()

check("LOW report has green colour", '#388e3c' in low_report_content)
check("LOW report says LOW", 'LOW' in low_report_content)
check("LOW report has safe language",
      'no significant security issues' in low_report_content.lower() or
      'no immediate action' in low_report_content.lower())
check("LOW report has all sections (header)",
      "vision-M Security Scan Report" in low_report_content)
check("LOW report has Executive Summary",
      "Executive Summary" in low_report_content)
check("LOW report has Remediation",
      "Remediation" in low_report_content)
check("LOW report has Footer",
      "Confidential Report" in low_report_content)


# ═══════════════════════════════════════════════════════════════════
# TEST 3: Markdown Format
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 3: Markdown Format (CRITICAL)")
print("=" * 60)

report_dir_md = tempfile.mkdtemp(prefix="vision_m_reports_md_")
report_path_md = generate_report(
    result_crit, fmt="markdown", output_dir=report_dir_md
)
check("Markdown report exists", os.path.exists(report_path_md))
check("Markdown .md extension", report_path_md.endswith(".md"))

with open(report_path_md, 'r') as f:
    md_content = f.read()

check("MD: vision-M header", "vision-M Security Scan Report" in md_content)
check("MD: Executive Summary", "Executive Summary" in md_content)
check("MD: Risk Score/Level", "Risk Score" in md_content)
check("MD: Findings", "Findings" in md_content)
check("MD: Remediation", "Remediation" in md_content)
check("MD: Scan Metadata", "Scan Metadata" in md_content)
check("MD: Footer/confidential", "Confidential Report" in md_content)
check("MD: CRITICAL in markdown", "CRITICAL" in md_content)

print(f"\n  Markdown report path: {report_path_md}")
print(f"  Markdown report size: {len(md_content)} bytes")


# ═══════════════════════════════════════════════════════════════════
# TEST 4: LOW Report — Markdown Format
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 4: Markdown Format (LOW)")
print("=" * 60)

report_dir_md_low = tempfile.mkdtemp(prefix="vision_m_reports_md_low_")
report_path_md_low = generate_report(
    result_low, fmt="markdown", output_dir=report_dir_md_low
)
check("LOW Markdown report exists", os.path.exists(report_path_md_low))

with open(report_path_md_low, 'r') as f:
    md_low_content = f.read()

check("MD LOW: no CRITICAL language", 'CRITICAL' not in md_low_content)
check("MD LOW: LOW present", 'LOW' in md_low_content)
check("MD LOW: safe language",
      'no significant security issues' in md_low_content.lower() or
      'no immediate action' in md_low_content.lower())


# ═══════════════════════════════════════════════════════════════════
# TEST 5: Print HTML Sample
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 5: HTML Report Sample (first 500 chars)")
print("=" * 60)

with open(report_path_html, 'r') as f:
    sample = f.read(500)

print(f"\n--- BEGIN HTML SAMPLE ---\n{sample}\n--- END HTML SAMPLE ---\n")
check("HTML sample starts with <!DOCTYPE", sample.startswith("<!DOCTYPE html>"))


# ═══════════════════════════════════════════════════════════════════
# TEST 6: Concurrent reports don't collide
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TEST 6: Multiple Reports — Unique Filenames")
print("=" * 60)

report_dir6 = tempfile.mkdtemp(prefix="vision_m_multi_")
r1 = generate_report(result_crit, fmt="html", output_dir=report_dir6)
r2 = generate_report(result_crit, fmt="html", output_dir=report_dir6)
r3 = generate_report(result_crit, fmt="markdown", output_dir=report_dir6)
r4 = generate_report(result_low, fmt="html", output_dir=report_dir6)

check("4 unique report paths", len({r1, r2, r3, r4}) == 4)
check("all 4 reports exist", all(os.path.exists(r) for r in [r1, r2, r3, r4]))


# ═══════════════════════════════════════════════════════════════════
# FINAL
# ═══════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print(f"RESULTS: {PASS} passed, {FAIL} failed")
print("=" * 60)

if __name__ == "__main__":
    sys.exit(0 if FAIL == 0 else 1)
