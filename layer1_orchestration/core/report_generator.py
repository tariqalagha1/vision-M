"""
Report Generator for vision-M Security Scanner.

Generates HTML and Markdown reports from scan result dictionaries.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone


def generate_report(result: dict, format: str = "html") -> str:
    """
    Generate a security scan report from a result dictionary.

    Args:
        result: Dict with keys: target, risk_level, summary, findings (list of dicts),
                evidence_references, completed_subtasks, requests_consumed, timestamp.
        format: 'html' for a complete HTML document with inline dark-themed CSS,
                'markdown' for a clean Markdown document.

    Returns:
        The report as a string.
    """
    if format == "html":
        return _generate_html_report(result)
    elif format == "markdown":
        return _generate_markdown_report(result)
    else:
        raise ValueError(f"Unsupported format: {format!r}. Use 'html' or 'markdown'.")


def save_report(
    result: dict,
    output_dir: str | None = None,
    format: str = "html",
) -> str:
    """
    Generate a report and save it to disk.

    Args:
        result: Scan result dict (same as generate_report).
        output_dir: Directory to save the report. Defaults to
                    /data/workspace/vision-M/layer1_orchestration/reports/
        format: 'html' or 'markdown'.

    Returns:
        Full file path to the saved report.
    """
    if output_dir is None:
        output_dir = "/data/workspace/vision-M/layer1_orchestration/reports"

    os.makedirs(output_dir, exist_ok=True)

    report_content = generate_report(result, format=format)

    # Derive a discovery_id from the target
    target = result.get("target", "unknown")
    discovery_id = _sanitize_target(target)

    ext = "html" if format == "html" else "md"
    filename = f"{discovery_id}.{ext}"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_content)

    return filepath


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_EXEC_SUMMARIES: dict[str, str] = {
    "CRITICAL": (
        "The scan has identified critical-severity issues that demand immediate attention. "
        "Sensitive credentials and exploitable misconfigurations were detected that could lead "
        "to full compromise of the target environment. Remediation should be treated as an "
        "urgent priority."
    ),
    "HIGH": (
        "The scan uncovered high-severity vulnerabilities that present a significant risk to "
        "the target's security posture. While no active exploitation was confirmed, the "
        "exposed attack surface warrants prompt investigation and remediation."
    ),
    "MEDIUM": (
        "The scan detected medium-severity findings that, while not immediately exploitable, "
        "increase the overall risk surface. Addressing these issues will strengthen the "
        "target's defense-in-depth posture and reduce the likelihood of escalation."
    ),
    "LOW": (
        "The scan returned low-severity observations — informational or hygiene items that "
        "pose minimal direct risk. No urgent action is required, though periodic review is "
        "recommended to ensure the baseline remains favourable."
    ),
}

_RISK_COLORS: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#16a34a",
}

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#6b7280",
}


def _sanitize_target(target: str) -> str:
    """Convert a target string to a filesystem-safe identifier."""
    return target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")


def _format_timestamp(ts: str) -> str:
    """Format an ISO-8601 timestamp into a human-readable string."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return ts
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _exec_summary(risk_level: str) -> str:
    """Return the executive summary paragraph for a given risk level."""
    return _EXEC_SUMMARIES.get(risk_level.upper(), _EXEC_SUMMARIES["MEDIUM"])


def _risk_color(risk_level: str) -> str:
    return _RISK_COLORS.get(risk_level.upper(), "#6b7280")


def _severity_color(severity: str) -> str:
    return _SEVERITY_COLORS.get(severity.lower(), "#6b7280")


def _severity_badge_html(severity: str) -> str:
    color = _severity_color(severity)
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'background:{color};color:#fff;font-size:12px;font-weight:600;'
        f'text-transform:uppercase;">{severity}</span>'
    )


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def _generate_html_report(result: dict) -> str:
    target = result.get("target", "N/A")
    risk_level = result.get("risk_level", "UNKNOWN")
    summary = result.get("summary", "No summary provided.")
    findings = result.get("findings", [])
    evidence = result.get("evidence_references", [])
    completed = result.get("completed_subtasks", [])
    requests = result.get("requests_consumed", 0)
    timestamp = result.get("timestamp", "")

    color = _risk_color(risk_level)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vision-M Security Scan Report — {_escape_html(target)}</title>
</head>
<body style="margin:0;padding:0;background:#0f1117;color:#e1e4e8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;line-height:1.6;">
<div style="max-width:900px;margin:0 auto;padding:40px 24px;">

<!-- Header -->
<div style="border-bottom:2px solid #30363d;padding-bottom:20px;margin-bottom:32px;">
<h1 style="margin:0;font-size:28px;color:#58a6ff;">&#128737; vision-M Security Scan Report</h1>
<p style="margin:8px 0 0;color:#8b949e;">Target: <strong style="color:#c9d1d9;">{_escape_html(target)}</strong></p>
</div>

<!-- Executive Summary -->
<h2 style="margin:0 0 12px;color:#f0f6fc;font-size:20px;">Executive Summary</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:28px;">
<p style="margin:0;color:#c9d1d9;">{_exec_summary(risk_level)}</p>
<p style="margin:12px 0 0;color:#8b949e;">{_escape_html(summary)}</p>
</div>

<!-- Risk Score Card -->
<h2 style="margin:0 0 12px;color:#f0f6fc;font-size:20px;">Risk Score</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;margin-bottom:28px;text-align:center;">
<div style="display:inline-block;width:120px;height:120px;border-radius:50%;background:{color};line-height:120px;font-size:36px;font-weight:700;color:#fff;margin-bottom:12px;">{_escape_html(risk_level)}</div>
<p style="margin:0;color:#8b949e;">Overall risk classification for this scan</p>
</div>

<!-- Findings -->
<h2 style="margin:0 0 12px;color:#f0f6fc;font-size:20px;">Findings</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:28px;">
<table style="width:100%;border-collapse:collapse;">
<thead>
<tr style="background:#21262d;">
<th style="padding:12px 16px;text-align:left;font-size:13px;font-weight:600;color:#c9d1d9;border-bottom:1px solid #30363d;">Title</th>
<th style="padding:12px 16px;text-align:left;font-size:13px;font-weight:600;color:#c9d1d9;border-bottom:1px solid #30363d;">Severity</th>
<th style="padding:12px 16px;text-align:left;font-size:13px;font-weight:600;color:#c9d1d9;border-bottom:1px solid #30363d;">Description</th>
</tr>
</thead>
<tbody>
{_findings_rows_html(findings)}
</tbody>
</table>
</div>
<p style="margin:0 0 28px;color:#8b949e;font-size:13px;">Total findings: {len(findings)}</p>

<!-- Remediation Recommendations -->
<h2 style="margin:0 0 12px;color:#f0f6fc;font-size:20px;">Remediation Recommendations</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:28px;">
{_remediation_html(findings)}
</div>

<!-- Scan Metadata -->
<h2 style="margin:0 0 12px;color:#f0f6fc;font-size:20px;">Scan Metadata</h2>
<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:28px;">
<table style="width:100%;border-collapse:collapse;">
<tr><td style="padding:6px 8px;color:#8b949e;width:180px;">Target</td><td style="padding:6px 8px;color:#c9d1d9;font-weight:500;">{_escape_html(target)}</td></tr>
<tr><td style="padding:6px 8px;color:#8b949e;">Timestamp</td><td style="padding:6px 8px;color:#c9d1d9;">{_format_timestamp(timestamp)}</td></tr>
<tr><td style="padding:6px 8px;color:#8b949e;">Requests Consumed</td><td style="padding:6px 8px;color:#c9d1d9;">{requests}</td></tr>
<tr><td style="padding:6px 8px;color:#8b949e;">Completed Subtasks</td><td style="padding:6px 8px;color:#c9d1d9;">{', '.join(_escape_html(t) for t in completed)}</td></tr>
<tr><td style="padding:6px 8px;color:#8b949e;">Evidence References</td><td style="padding:6px 8px;color:#c9d1d9;">{', '.join(_escape_html(e) for e in evidence) if evidence else 'None'}</td></tr>
</table>
</div>

<!-- Footer -->
<div style="border-top:1px solid #30363d;padding-top:16px;text-align:center;">
<p style="margin:0;color:#484f58;font-size:13px;">Generated by vision-M</p>
</div>

</div>
</body>
</html>"""


def _findings_rows_html(findings: list) -> str:
    if not findings:
        return (
            '<tr><td colspan="3" style="padding:20px 16px;text-align:center;'
            'color:#8b949e;">No findings to display.</td></tr>'
        )
    rows: list[str] = []
    for i, f in enumerate(findings):
        bg = "#161b22" if i % 2 == 0 else "#1c2128"
        title = _escape_html(f.get("title", "Untitled"))
        severity = f.get("severity", "info")
        badge = _severity_badge_html(severity)
        description = _escape_html(f.get("description", ""))
        rows.append(
            f'<tr style="background:{bg};">'
            f'<td style="padding:12px 16px;color:#c9d1d9;font-weight:500;">{title}</td>'
            f'<td style="padding:12px 16px;">{badge}</td>'
            f'<td style="padding:12px 16px;color:#8b949e;">{description}</td>'
            f"</tr>"
        )
    return "\n".join(rows)


def _remediation_html(findings: list) -> str:
    if not findings:
        return '<p style="margin:0;color:#8b949e;">No remediation recommendations — no findings detected.</p>'
    items: list[str] = []
    for f in findings:
        title = _escape_html(f.get("title", "Untitled"))
        severity = f.get("severity", "info").capitalize()
        description = _escape_html(f.get("description", ""))
        items.append(
            f'<div style="background:#1c2128;border-left:3px solid {_severity_color(severity)};'
            f'border-radius:4px;padding:12px 16px;margin-bottom:10px;">'
            f'<strong style="color:#c9d1d9;">[{severity}] {title}</strong>'
            f'<p style="margin:6px 0 0;color:#8b949e;">{description}</p>'
            f"</div>"
        )
    return "\n".join(items)


def _escape_html(text: str) -> str:
    """Minimal HTML-escaping for safety."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def _generate_markdown_report(result: dict) -> str:
    target = result.get("target", "N/A")
    risk_level = result.get("risk_level", "UNKNOWN")
    summary = result.get("summary", "No summary provided.")
    findings = result.get("findings", [])
    evidence = result.get("evidence_references", [])
    completed = result.get("completed_subtasks", [])
    requests = result.get("requests_consumed", 0)
    timestamp = result.get("timestamp", "")

    lines: list[str] = []

    # Title
    lines.append("# 🛡️ vision-M Security Scan Report")
    lines.append("")
    lines.append(f"**Target:** `{target}`")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(_exec_summary(risk_level))
    lines.append("")
    lines.append(f"> {summary}")
    lines.append("")

    # Risk Score
    lines.append("## Risk Score")
    lines.append("")
    lines.append(f"**Overall Risk Level:** `{risk_level}`")
    lines.append("")

    # Findings
    lines.append("## Findings")
    lines.append("")
    if findings:
        lines.append("| # | Title | Severity | Description |")
        lines.append("|---|-------|----------|-------------|")
        for i, f in enumerate(findings, 1):
            title = f.get("title", "Untitled")
            severity = f.get("severity", "info")
            description = f.get("description", "")
            lines.append(f"| {i} | {title} | **{severity.upper()}** | {description} |")
        lines.append("")
        lines.append(f"*Total findings: {len(findings)}*")
    else:
        lines.append("*No findings to display.*")
    lines.append("")

    # Remediation
    lines.append("## Remediation Recommendations")
    lines.append("")
    if findings:
        for f in findings:
            title = f.get("title", "Untitled")
            severity = f.get("severity", "info").upper()
            description = f.get("description", "")
            lines.append(f"- **[{severity}]** {title} — {description}")
    else:
        lines.append("*No remediation recommendations — no findings detected.*")
    lines.append("")

    # Scan Metadata
    lines.append("## Scan Metadata")
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Timestamp:** {_format_timestamp(timestamp)}")
    lines.append(f"- **Requests Consumed:** {requests}")
    lines.append(f"- **Completed Subtasks:** {', '.join(completed)}")
    evidence_str = ", ".join(evidence) if evidence else "None"
    lines.append(f"- **Evidence References:** {evidence_str}")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Generated by vision-M*")

    return "\n".join(lines)
