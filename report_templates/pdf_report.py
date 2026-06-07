"""PDF report generation module using ReportLab."""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
    Image,
)
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from datetime import datetime
from typing import Dict, List, Any
import io


def generate_pdf_report(
    report_data: Dict[str, Any], filename: str
) -> None:
    """
    Generate a PDF report from vulnerability data.

    Args:
        report_data: Dictionary containing report data
        filename: Output PDF filename
    """
    doc = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.5 * inch, bottomMargin=0.5 * inch)

    elements = []
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#667eea"),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
    )

    subtitle_style = ParagraphStyle(
        "CustomSubtitle",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#333333"),
        spaceAfter=12,
        alignment=TA_CENTER,
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#667eea"),
        spaceAfter=12,
        spaceBefore=12,
        fontName="Helvetica-Bold",
    )

    body_style = ParagraphStyle(
        "CustomBody",
        parent=styles["BodyText"],
        fontSize=10,
        alignment=TA_JUSTIFY,
        spaceAfter=8,
    )

    # Title Page
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("☁️ Cloud Misconfiguration Report", title_style))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(f"Security Assessment for <b>{report_data['domain']}</b>", subtitle_style))
    elements.append(Spacer(1, 0.3 * inch))

    # Risk badge
    risk_level = report_data["risk_level"]
    risk_color_map = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#f57c00",
        "MEDIUM": "#fbc02d",
        "LOW": "#388e3c",
    }
    risk_color = risk_color_map.get(risk_level, "#757575")

    risk_badge_style = ParagraphStyle(
        "RiskBadge",
        parent=styles["Normal"],
        fontSize=16,
        textColor=colors.white,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        backColor=colors.HexColor(risk_color),
        spaceAfter=12,
    )

    elements.append(Paragraph(f"Overall Risk Level: {risk_level}", risk_badge_style))
    elements.append(Spacer(1, 0.3 * inch))

    # Metadata table
    metadata = [
        ["Target Domain", report_data["domain"]],
        ["Report Date", report_data["timestamp"]],
        ["Risk Score", f"{report_data['risk_score']}/100"],
        ["Total Vulnerabilities", str(report_data["total_vulns"])],
    ]

    metadata_table = Table(metadata, colWidths=[2 * inch, 4 * inch])
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                ("BACKGROUND", (1, 0), (1, -1), colors.white),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#667eea")),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#ddd")),
            ]
        )
    )
    elements.append(metadata_table)
    elements.append(Spacer(1, 0.3 * inch))

    # Statistics
    elements.append(Paragraph("Vulnerability Summary", heading_style))

    stats_data = [
        ["Total", "Critical", "High", "Medium", "Low"],
        [
            str(report_data["total_vulns"]),
            str(report_data["critical_count"]),
            str(report_data["high_count"]),
            str(report_data["medium_count"]),
            str(report_data["low_count"]),
        ],
    ]

    stats_table = Table(stats_data, colWidths=[1 * inch] * 5)
    stats_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#667eea")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                ("TOPPADDING", (0, 0), (-1, 0), 10),
                ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#667eea")),
                ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#d32f2f")),
                ("BACKGROUND", (2, 1), (2, 1), colors.HexColor("#f57c00")),
                ("BACKGROUND", (3, 1), (3, 1), colors.HexColor("#fbc02d")),
                ("BACKGROUND", (4, 1), (4, 1), colors.HexColor("#388e3c")),
                ("TEXTCOLOR", (0, 1), (-1, 1), colors.white),
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 1), (-1, 1), 11),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ("TOPPADDING", (0, 1), (-1, 1), 8),
                ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#ddd")),
            ]
        )
    )
    elements.append(stats_table)
    elements.append(PageBreak())

    # S3 Vulnerabilities
    s3_vulns = report_data.get("s3_vulns", [])
    if s3_vulns:
        elements.append(Paragraph("🪣 Amazon S3 Vulnerabilities", heading_style))

        for vuln in s3_vulns:
            vuln_data = [
                ["Bucket Name:", vuln["bucket_name"]],
                ["URL:", vuln["url"]],
                ["Risk Level:", vuln["risk_level"]],
                ["Vulnerabilities:", ", ".join(vuln.get("vulnerabilities", []))],
            ]

            vuln_table = Table(vuln_data, colWidths=[1.5 * inch, 4.5 * inch])
            vuln_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#667eea")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.15 * inch))

        elements.append(PageBreak())

    # Azure Vulnerabilities
    azure_vulns = report_data.get("azure_vulns", [])
    if azure_vulns:
        elements.append(Paragraph("☁️ Microsoft Azure Vulnerabilities", heading_style))

        for vuln in azure_vulns:
            vuln_data = [
                ["Account Name:", vuln["account_name"]],
                ["Container Name:", vuln["container_name"]],
                ["URL:", vuln["url"]],
                ["Risk Level:", vuln["risk_level"]],
                ["Vulnerabilities:", ", ".join(vuln.get("vulnerabilities", []))],
            ]

            vuln_table = Table(vuln_data, colWidths=[1.5 * inch, 4.5 * inch])
            vuln_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
                        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#667eea")),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#ddd")),
                    ]
                )
            )
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.15 * inch))

        elements.append(PageBreak())

    # Recommendations
    recommendations = report_data.get("recommendations", [])
    if recommendations:
        elements.append(Paragraph("🔒 Security Recommendations", heading_style))
        elements.append(Spacer(1, 0.1 * inch))

        for i, rec in enumerate(recommendations, 1):
            rec_para = Paragraph(f"<b>{i}.</b> {rec}", body_style)
            elements.append(rec_para)
            elements.append(Spacer(1, 0.08 * inch))

    # Footer
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("—" * 80, body_style))
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#999"),
        alignment=TA_CENTER,
    )
    elements.append(Paragraph(f"Cloud Misconfiguration Scanner | Generated: {report_data['timestamp']}", footer_style))
    elements.append(Paragraph(
        "This report was automatically generated as part of a security assessment.",
        footer_style,
    ))

    # Build PDF
    doc.build(elements)
