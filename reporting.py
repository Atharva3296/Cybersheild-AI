from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm

def create_pdf_report(results):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=16*mm,
                            leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("CyberShield AI - Security Analysis Report", styles["Title"]),
        Spacer(1, 8),
        Paragraph(f"Records analyzed: {len(results)}", styles["BodyText"]),
        Paragraph(f"Suspicious records: {(results['classification'] == 'Suspicious').sum()}", styles["BodyText"]),
        Spacer(1, 12)
    ]
    data = [["Source", "Classification", "Risk", "Score", "Reason"]]
    for _, r in results.head(35).iterrows():
        data.append([
            str(r.get("source", "sample"))[:18],
            str(r["classification"]),
            str(r["risk_level"]),
            str(r["anomaly_score"]),
            str(r["reason"])[:45]
        ])
    table = Table(data, colWidths=[28*mm, 30*mm, 18*mm, 20*mm, 75*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.35, colors.grey),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#EEF4FA")])
    ]))
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
