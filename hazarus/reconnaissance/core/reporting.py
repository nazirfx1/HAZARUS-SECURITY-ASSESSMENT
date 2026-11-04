"""
HAZARUS Reconnaissance Reporting
Markdown, PDF, and HTML report generation.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, UTC
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ReconReport:
    """Reconnaissance report data."""
    assessment_id: str
    target: str
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    phases: List[str]
    assets: Dict[str, List[Any]]
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class ReconReportGenerator:
    """Report generator for reconnaissance results."""

    def __init__(self, branding: bool = True):
        """
        Initialize report generator.

        Args:
            branding: Whether to include HAZARUS branding
        """
        self.branding = branding
        self.logger = logging.getLogger("hazarus.recon_reporting")

    def generate_markdown(self, report: ReconReport) -> str:
        """
        Generate Markdown report.

        Args:
            report: ReconReport data

        Returns:
            Markdown string
        """
        lines = []

        # Title
        if self.branding:
            lines.append("# 🔍 HAZARUS Reconnaissance Report")
        else:
            lines.append("# Reconnaissance Report")

        lines.append("")

        # Assessment metadata
        lines.append("## Assessment Information")
        lines.append("")
        lines.append(f"- **Assessment ID:** `{report.assessment_id}`")
        lines.append(f"- **Target:** {report.target}")
        lines.append(f"- **Started:** {report.started_at.isoformat()}")
        if report.completed_at:
            lines.append(f"- **Completed:** {report.completed_at.isoformat()}")
            duration = (report.completed_at - report.started_at).total_seconds()
            lines.append(f"- **Duration:** {duration:.2f} seconds")
        lines.append(f"- **Status:** {report.status}")
        lines.append("")

        # Phases
        lines.append("## Assessment Phases")
        lines.append("")
        for phase in report.phases:
            lines.append(f"- {phase}")
        lines.append("")

        # Assets by type
        lines.append("## Discovered Assets")
        lines.append("")

        for asset_type, assets in report.assets.items():
            if assets:
                lines.append(f"### {asset_type.replace('_', ' ').title()}")
                lines.append(f"**Count:** {len(assets)}")
                lines.append("")

                for asset in assets[:20]:  # Show first 20
                    if isinstance(asset, dict):
                        lines.append(f"- {asset.get('value', str(asset))}")
                    else:
                        lines.append(f"- {asset}")

                if len(assets) > 20:
                    lines.append(f"- ... and {len(assets) - 20} more")
                lines.append("")

        # Findings
        if report.findings:
            lines.append("## Security Findings")
            lines.append("")

            # Group by severity
            severity_order = ["critical", "high", "medium", "low", "info"]
            for severity in severity_order:
                severity_findings = [f for f in report.findings if f.get("severity") == severity]
                if severity_findings:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
                    lines.append(f"### {emoji.get(severity, '•')} {severity.upper()}")
                    lines.append("")

                    for finding in severity_findings:
                        lines.append(f"#### {finding.get('title', 'Untitled')}")
                        lines.append(f"**Type:** {finding.get('finding_type', 'Unknown')}")
                        lines.append(f"**Description:** {finding.get('description', 'No description')}")
                        if finding.get('evidence'):
                            lines.append(f"**Evidence:** `{finding.get('evidence')}`")
                        lines.append("")

        # Summary statistics
        lines.append("## Summary Statistics")
        lines.append("")
        total_assets = sum(len(assets) for assets in report.assets.values())
        lines.append(f"- **Total Assets:** {total_assets}")
        lines.append(f"- **Total Findings:** {len(report.findings)}")

        # Findings by severity
        severity_counts = {}
        for finding in report.findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"- **{severity.upper()} Findings:** {count}")

        lines.append("")

        # Branding footer
        if self.branding:
            lines.append("---")
            lines.append("")
            lines.append("*Generated by HAZARUS Security Assessment Framework*")
            lines.append("*Reconnaissance Module v2.0*")
            lines.append("")

        return "\n".join(lines)

    def generate_html(self, report: ReconReport) -> str:
        """
        Generate HTML report.

        Args:
            report: ReconReport data

        Returns:
            HTML string
        """
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HAZARUS Reconnaissance Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #DC2626 0%, #000000 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        h1, h2, h3, h4 {
            color: #DC2626;
        }
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-box {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #DC2626;
        }
        .finding {
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }
        .critical { background: #fee; border-color: #dc2626; }
        .high { background: #fef3c7; border-color: #f59e0b; }
        .medium { background: #fef9c3; border-color: #eab308; }
        .low { background: #f0fdf4; border-color: #22c55e; }
        .info { background: #eff6ff; border-color: #3b82f6; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #DC2626;
            color: white;
        }
    </style>
</head>
<body>
"""

        # Header
        html += f"""
    <div class="header">
        <h1>🔍 HAZARUS Reconnaissance Report</h1>
        <p>Target: {report.target}</p>
        <p>Assessment ID: {report.assessment_id}</p>
    </div>
"""

        # Assessment info
        html += """
    <div class="container">
        <h2>Assessment Information</h2>
        <table>
"""
        html += f"            <tr><th>Started</th><td>{report.started_at.isoformat()}</td></tr>"
        if report.completed_at:
            html += f"            <tr><th>Completed</th><td>{report.completed_at.isoformat()}</td></tr>"
            duration = (report.completed_at - report.started_at).total_seconds()
            html += f"            <tr><th>Duration</th><td>{duration:.2f} seconds</td></tr>"
        html += f"            <tr><th>Status</th><td>{report.status}</td></tr>"
        html += """
        </table>
    </div>
"""

        # Assets
        html += """
    <div class="container">
        <h2>Discovered Assets</h2>
        <div class="stat-grid">
"""
        total_assets = sum(len(assets) for assets in report.assets.values())
        html += f"            <div class='stat-box'><h3>Total Assets</h3><p>{total_assets}</p></div>"

        for asset_type, assets in report.assets.items():
            if assets:
                html += f"            <div class='stat-box'><h3>{asset_type.replace('_', ' ').title()}</h3><p>{len(assets)}</p></div>"

        html += """
        </div>
    </div>
"""

        # Findings
        if report.findings:
            html += """
    <div class="container">
        <h2>Security Findings</h2>
"""
            for finding in report.findings:
                severity = finding.get("severity", "info")
                html += f"""
        <div class="finding {severity}">
            <h4>{finding.get('title', 'Untitled')}</h4>
            <p><strong>Type:</strong> {finding.get('finding_type', 'Unknown')}</p>
            <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
"""
                if finding.get('evidence'):
                    html += f"            <p><strong>Evidence:</strong> <code>{finding.get('evidence')}</code></p>"
                html += """
        </div>
"""
            html += """
    </div>
"""

        # Footer
        html += """
    <div class="container" style="text-align: center; color: #666;">
        <p>Generated by HAZARUS Security Assessment Framework</p>
        <p>Reconnaissance Module v2.0</p>
    </div>
</body>
</html>
"""

        return html

    async def generate_pdf(self, report: ReconReport, output_path: str) -> bool:
        """
        Generate PDF report (requires weasyprint).

        Args:
            report: ReconReport data
            output_path: Path to save PDF

        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate HTML first
            html = self.generate_html(report)

            # Try to use weasyprint
            try:
                from weasyprint import HTML
                HTML(string=html).write_pdf(output_path)
                self.logger.info(f"PDF report saved to: {output_path}")
                return True
            except ImportError:
                self.logger.warning("weasyprint not installed, skipping PDF generation")
                return False

        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            return False

    async def save_report(
        self,
        report: ReconReport,
        output_dir: str,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """
        Save report in multiple formats.

        Args:
            report: ReconReport data
            output_dir: Output directory
            formats: List of formats (markdown, html, pdf)

        Returns:
            Dictionary of format -> file path
        """
        if formats is None:
            formats = ["markdown", "html"]

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        saved_files = {}

        # Markdown
        if "markdown" in formats or "md" in formats:
            md_path = output_path / f"{report.assessment_id}_report.md"
            md_content = self.generate_markdown(report)
            with open(md_path, "w") as f:
                f.write(md_content)
            saved_files["markdown"] = str(md_path)
            self.logger.info(f"Markdown report saved to: {md_path}")

        # HTML
        if "html" in formats:
            html_path = output_path / f"{report.assessment_id}_report.html"
            html_content = self.generate_html(report)
            with open(html_path, "w") as f:
                f.write(html_content)
            saved_files["html"] = str(html_path)
            self.logger.info(f"HTML report saved to: {html_path}")

        # PDF
        if "pdf" in formats:
            pdf_path = output_path / f"{report.assessment_id}_report.pdf"
            success = await self.generate_pdf(report, str(pdf_path))
            if success:
                saved_files["pdf"] = str(pdf_path)

        return saved_files
