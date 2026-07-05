from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


REPORT_DIR = Path("reports")


def _p(text: str, style) -> Paragraph:
    safe = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return Paragraph(safe, style)


def generate_pdf_report(scan_result: dict[str, Any], output_dir: Path = REPORT_DIR) -> Path:
    """Generate a PDF forensic investigation report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    case_id = scan_result["case_id"]
    repo_name = scan_result["summary"]["repo_name"]
    pdf_path = output_dir / f"{case_id}_{repo_name}_forensic_report.pdf"

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading = styles["Heading2"]
    normal = styles["BodyText"]
    small = ParagraphStyle("Small", parent=normal, fontSize=8, leading=10)

    story = []
    story.append(_p("Git Repository Forensics Investigation Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    summary = scan_result["summary"]
    metrics = scan_result["metrics"]

    case_data = [
        ["Case ID", scan_result["case_id"]],
        ["Repository Name", summary.get("repo_name", "")],
        ["Repository Path", summary.get("repo_path", "")],
        ["Investigator", scan_result.get("investigator_name", "")],
        ["Scan Date", scan_result.get("scan_date", "")],
        ["Active Branch", summary.get("active_branch", "")],
    ]
    table = Table(case_data, colWidths=[1.8 * inch, 4.5 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    story.append(_p("Repository Summary", heading))
    metrics_data = [
        ["Metric", "Value"],
        ["Total Commits Analyzed", metrics.get("total_commits_analyzed", 0)],
        ["Total Contributors", metrics.get("total_contributors", 0)],
        ["Total Findings", metrics.get("total_findings", 0)],
        ["Suspicious Commits", metrics.get("suspicious_commits", 0)],
        ["Secrets Detected", metrics.get("secrets_detected", 0)],
        ["Deleted Sensitive Files", metrics.get("deleted_sensitive_files", 0)],
        ["High Risk Findings", metrics.get("high_risk_findings", 0)],
    ]
    table = Table(metrics_data, colWidths=[3.2 * inch, 2.0 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 0.25 * inch))

    story.append(_p("Major Findings", heading))
    findings = scan_result.get("findings", [])
    if not findings:
        story.append(_p("No suspicious findings were detected in the scanned repository.", normal))
    else:
        finding_rows = [["Type", "Severity", "Score", "Commit", "File", "Evidence"]]
        for f in findings[:25]:
            finding_rows.append(
                [
                    _p(f.get("finding_type", ""), small),
                    _p(f.get("severity", ""), small),
                    str(f.get("risk_score", "")),
                    _p(f.get("commit_hash", ""), small),
                    _p(f.get("file_path", ""), small),
                    _p(f.get("evidence", ""), small),
                ]
            )
        table = Table(finding_rows, colWidths=[1.25 * inch, 0.75 * inch, 0.45 * inch, 0.8 * inch, 1.2 * inch, 2.0 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(table)

    story.append(PageBreak())
    story.append(_p("Recommendations", heading))
    if findings:
        for idx, f in enumerate(findings[:15], 1):
            story.append(_p(f"{idx}. {f.get('finding_type', '')}: {f.get('recommendation', '')}", normal))
            story.append(Spacer(1, 0.08 * inch))
    else:
        story.append(_p("Continue periodic Git history audits and enforce secure development practices.", normal))

    story.append(Spacer(1, 0.25 * inch))
    story.append(_p("Conclusion", heading))
    conclusion = (
        "This report summarizes forensic indicators discovered from the Git repository history. "
        "Findings should be reviewed by the security team and repository owner. Critical and high-risk "
        "items such as exposed secrets, deleted sensitive files, and authentication logic changes should be prioritized."
    )
    story.append(_p(conclusion, normal))

    doc.build(story)
    return pdf_path
