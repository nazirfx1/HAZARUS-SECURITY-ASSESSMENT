"""
HAZARUS Report Engine
Core report generation engine.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json


@dataclass
class ReportConfig:
    """Report configuration."""
    assessment_id: str
    format: str  # html, pdf, json, markdown
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_evidence: bool = True
    include_recommendations: bool = True
    output_path: Optional[str] = None


class ReportEngine:
    """Report generation engine."""

    def __init__(self, reports_dir: Optional[Path] = None):
        self.logger = logging.getLogger("hazarus.report_engine")

        if reports_dir is None:
            reports_dir = Path.home() / ".hazarus" / "reports"

        self.reports_dir = reports_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    async def generate(self, config: ReportConfig, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate assessment report."""
        self.logger.info(f"Generating {config.format} report for {config.assessment_id}")

        result = {
            "assessment_id": config.assessment_id,
            "format": config.format,
            "generated_at": datetime.utcnow().isoformat(),
            "status": "pending",
            "output_path": None
        }

        try:
            # Generate report based on format
            if config.format == "html":
                from .html_report import HTMLReport
                generator = HTMLReport()
                content = await generator.generate(assessment_data)
                output_path = self._save_report(config.assessment_id, "html", content)

            elif config.format == "pdf":
                from .pdf_report import PDFReport
                generator = PDFReport()
                content = await generator.generate(assessment_data)
                output_path = self._save_report(config.assessment_id, "pdf", content, binary=True)

            elif config.format == "json":
                from .json_report import JSONReport
                generator = JSONReport()
                content = await generator.generate(assessment_data)
                output_path = self._save_report(config.assessment_id, "json", content)

            elif config.format == "markdown":
                from .markdown_report import MarkdownReport
                generator = MarkdownReport()
                content = await generator.generate(assessment_data)
                output_path = self._save_report(config.assessment_id, "md", content)

            else:
                raise ValueError(f"Unsupported format: {config.format}")

            result["status"] = "completed"
            result["output_path"] = str(output_path)

            self.logger.info(f"Report generated: {output_path}")

        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            result["status"] = "failed"
            result["error"] = str(e)

        return result

    def _save_report(self, assessment_id: str, extension: str, content: str, binary: bool = False) -> Path:
        """Save report to disk."""
        filename = f"{assessment_id}_report.{extension}"
        output_path = self.reports_dir / filename

        mode = "wb" if binary else "w"
        data = content if binary else content

        with open(output_path, mode) as f:
            f.write(data)

        return output_path

    def _generate_markdown(self, assessment_data: Dict[str, Any]) -> str:
        """Generate markdown report."""
        md = []

        md.append(f"# HAZARUS Security Assessment Report")
        md.append(f"")
        md.append(f"**Assessment ID:** {assessment_data.get('assessment_id', 'N/A')}")
        md.append(f"**Generated:** {datetime.utcnow().isoformat()}")
        md.append(f"")
        md.append("---")
        md.append(f"")

        # Executive Summary
        if assessment_data.get("executive_summary"):
            md.append("## Executive Summary")
            md.append("")
            md.append(assessment_data["executive_summary"])
            md.append("")

        # Findings
        if assessment_data.get("findings"):
            md.append("## Findings")
            md.append("")
            for finding in assessment_data["findings"]:
                md.append(f"- **{finding.get('title', 'Untitled')}** ({finding.get('severity', 'Unknown')})")
                md.append(f"  {finding.get('description', '')}")
                md.append("")

        # Recommendations
        if assessment_data.get("recommendations"):
            md.append("## Recommendations")
            md.append("")
            for rec in assessment_data["recommendations"]:
                md.append(f"- {rec}")
            md.append("")

        return "\n".join(md)

    def get_report_path(self, assessment_id: str, format: str) -> Optional[Path]:
        """Get existing report path."""
        filename = f"{assessment_id}_report.{format}"
        output_path = self.reports_dir / filename

        if output_path.exists():
            return output_path

        return None
