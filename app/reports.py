from datetime import UTC, datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

INK = colors.HexColor("#1e2a28")
MUTED = colors.HexColor("#586864")
LINE = colors.HexColor("#d9dfdd")
ACCENT = colors.HexColor("#0e6b5c")

SEVERITY = {
    "critical": ("Crítico", colors.HexColor("#b3261e")),
    "high": ("Alto", colors.HexColor("#a63f00")),
    "medium": ("Medio", colors.HexColor("#7a5c00")),
    "low": ("Bajo", colors.HexColor("#41566e")),
}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _p(text: str) -> str:
    """Escapa texto externo (nombres, URL, mensajes del escáner) para el markup de reportlab."""
    return escape(str(text))


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(doc.leftMargin, 1.2 * cm, "Cybersec SaaS · Informe de seguridad web")
    canvas.drawRightString(A4[0] - doc.rightMargin, 1.2 * cm, f"Página {doc.page}")
    canvas.restoreState()


def build_pdf_report(target_name: str, target_url: str, owner_id: int, findings: list[dict]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=f"Informe de seguridad - {target_name}",
        author="Cybersec SaaS",
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    base = getSampleStyleSheet()["Normal"]
    body = ParagraphStyle("Body", parent=base, fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK, alignment=TA_LEFT)
    muted = ParagraphStyle("Muted", parent=body, fontSize=9, textColor=MUTED)
    title = ParagraphStyle("Title", parent=body, fontName="Helvetica-Bold", fontSize=20, leading=24, spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=body, fontName="Helvetica-Bold", fontSize=12, leading=16, spaceBefore=14, spaceAfter=6)
    finding_title = ParagraphStyle("FindingTitle", parent=body, fontName="Helvetica-Bold", fontSize=10.5, leading=14)

    ordered = sorted(findings, key=lambda f: ORDER.get(f.get("severity"), 9))
    counts = {key: sum(1 for f in ordered if f.get("severity") == key) for key in SEVERITY}

    story = [
        Paragraph("Informe de seguridad web", title),
        Paragraph(_p(target_name), ParagraphStyle("Name", parent=body, fontSize=12, leading=16)),
        Paragraph(_p(target_url), muted),
        Paragraph(f"Generado el {datetime.now(UTC).strftime('%d/%m/%Y a las %H:%M UTC')}", muted),
        Spacer(1, 0.5 * cm),
    ]

    if not ordered:
        story.append(Paragraph("El último escaneo no encontró hallazgos.", body))
    else:
        resumen = ", ".join(
            f"{counts[key]} {SEVERITY[key][0].lower() if counts[key] == 1 else SEVERITY[key][0].lower() + 's'}"
            for key in SEVERITY
            if counts[key]
        )
        story.append(Paragraph("Resumen", h2))
        story.append(Paragraph(f"{len(ordered)} {'hallazgo' if len(ordered) == 1 else 'hallazgos'}: {resumen}.", body))
        story.append(Paragraph("Hallazgos", h2))

        for f in ordered:
            label, color = SEVERITY.get(f.get("severity"), (str(f.get("severity")), MUTED))
            head = Table(
                [[Paragraph(f'<font color="{color.hexval().replace("0x", "#")}"><b>{_p(label)}</b></font>', body), Paragraph(_p(f["title"]), finding_title)]],
                colWidths=[2.2 * cm, 14.8 * cm],
            )
            head.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("LINEBEFORE", (0, 0), (0, 0), 0, colors.white),
            ]))
            block = [
                head,
                Spacer(1, 0.1 * cm),
                Paragraph(_p(f["description"]), body),
                Spacer(1, 0.1 * cm),
                Paragraph(f"<b>Cómo corregirlo.</b> {_p(f['remediation'])}", body),
                Spacer(1, 0.25 * cm),
            ]
            rule = Table([[""]], colWidths=[17 * cm], rowHeights=[1])
            rule.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 0.5, LINE)]))
            story.append(KeepTogether(block + [rule, Spacer(1, 0.2 * cm)]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf
