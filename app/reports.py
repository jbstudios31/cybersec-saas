from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_pdf_report(target_name: str, target_url: str, owner_id: int, findings: list[dict]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Reporte de seguridad - {target_name}",
        author="Cybersec SaaS",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=16,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=12,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=colors.HexColor("#4b5563"),
        spaceAfter=8,
    )
    body_style = styles["Normal"]
    severity_colors = {
        "critical": colors.HexColor("#dc2626"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#d97706"),
        "low": colors.HexColor("#65a30d"),
    }

    story = []
    story.append(Paragraph("Reporte de Seguridad Cibernética", title_style))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"<b>Objetivo:</b> {target_name}", body_style))
    story.append(Paragraph(f"<b>URL:</b> {target_url}", body_style))
    story.append(Paragraph(f"<b>Propietario ID:</b> {owner_id}", body_style))
    story.append(Paragraph(
        f"<b>Fecha del reporte:</b> {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')}",
        body_style,
    ))
    story.append(Spacer(1, 0.6 * cm))

    if not findings:
        story.append(Paragraph("No se encontraron hallazgos en el último escaneo.", body_style))
    else:
        story.append(Paragraph(f"Hallazgos ({len(findings)})", subtitle_style))
        story.append(Spacer(1, 0.3 * cm))

        data = [["Severidad", "Título", "Descripción", "Corrección"]]
        for f in findings:
            data.append([
                Paragraph(f"<b>{f['severity'].upper()}</b>", body_style),
                Paragraph(f["title"], body_style),
                Paragraph(f["description"], body_style),
                Paragraph(f["remediation"], body_style),
            ])

        table = Table(data, colWidths=[2.2 * cm, 4.2 * cm, 6.5 * cm, 6.5 * cm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        for i, f in enumerate(findings, start=1):
            sev_color = severity_colors.get(f["severity"], colors.HexColor("#6b7280"))
            table.setStyle(TableStyle([
                ("TEXTCOLOR", (0, i), (0, i), sev_color),
                ("FONTNAME", (0, i), (0, i), "Helvetica-Bold"),
            ]))

        story.append(table)

    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf
