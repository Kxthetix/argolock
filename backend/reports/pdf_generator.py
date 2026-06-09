"""PDF report generator using Jinja2 + WeasyPrint."""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader
from loguru import logger

from app.config import settings


async def generate_pdf(report_data: Dict[str, Any], scan_id: str) -> str:
    """Render HTML template and convert to PDF."""
    try:
        import weasyprint
    except ImportError:
        raise RuntimeError("WeasyPrint not installed. Install it with: pip install weasyprint")

    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html")

    # Prepare context
    context = {
        **report_data,
        "generated_at_formatted": datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC"),
        "severity_colors": {
            "critical": "#FF3B30",
            "high": "#FF9500",
            "medium": "#FFCC00",
            "low": "#34C759",
            "info": "#007AFF",
        },
    }

    html_content = template.render(**context)

    # Convert to PDF
    os.makedirs(settings.reports_dir, exist_ok=True)
    pdf_path = os.path.join(settings.reports_dir, f"argolock_report_{scan_id}.pdf")

    pdf = weasyprint.HTML(string=html_content).write_pdf()
    with open(pdf_path, "wb") as f:
        f.write(pdf)

    logger.info(f"PDF report written to {pdf_path}")
    return pdf_path
