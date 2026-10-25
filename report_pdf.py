import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def build_pdf(r):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, title="APK Forensic Report",
        leftMargin=40, rightMargin=40, topMargin=40, bottomMargin=40,
    )
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["BodyText"],
                           fontSize=8, leading=10, wordWrap="CJK")

    def P(text):
        return Paragraph(escape(str(text)), small)

    level_color = {"LOW": "#16a34a", "MEDIUM": "#d97706", "HIGH": "#dc2626"}
    color = level_color.get(r["level"], "#000000")

    story = []
    story.append(Paragraph("APK Forensic Analysis Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.now():%Y-%m-%d %H:%M}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        f'Risk score: <font color="{color}"><b>{r["score"]}/100 ({r["level"]})</b></font>',
        styles["Heading2"]))

    story.append(Paragraph("Why this score", styles["Heading3"]))
    for reason in (r["reasons"] or ["No risky indicators found"]):
        story.append(P("- " + reason))
    story.append(Spacer(1, 10))

    cert = r["certificate"]["subject"] if r.get("certificate") else "N/A"
    vt = r.get("virustotal", {})
    if vt.get("status") == "found":
        vt_text = (f'{vt["malicious"]} malicious, {vt["suspicious"]} suspicious, '
                   f'{vt["harmless"] + vt["undetected"]} clean/undetected')
    else:
        vt_text = "Not available (" + str(vt.get("status")) + ")"

    rows = [
        ["App name", r["app_name"]],
        ["Package", r["package"]],
        ["Version", r["version"]],
        ["MD5", r["md5"]],
        ["SHA256", r["sha256"]],
        ["Certificate", cert],
        ["Permissions", len(r["permissions"])],
        ["Exported components", len(r["exported_components"])],
        ["Public IPs", ", ".join(r["ips"]) or "None"],
        ["VirusTotal", vt_text],
    ]
    table = Table([[P(k), P(v)] for k, v in rows], colWidths=[110, 400])
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(Paragraph("App details", styles["Heading3"]))
    story.append(table)
    story.append(Spacer(1, 10))

    # ---- third-party libraries ----
    libs = r.get("libraries", {})
    vuln = r.get("vuln", {})
    story.append(Paragraph(
        f"Evidence: third-party libraries ({len(libs)} detected)", styles["Heading3"]))
    vulnerable = vuln.get("vulnerable", [])
    if vulnerable:
        for v in vulnerable:
            story.append(P(f"- VULNERABLE: {v['name']} {v['version']} -> "
                           f"{', '.join(v['ids'][:5])}"))
    elif vuln.get("status") == "ok":
        story.append(P("- No known vulnerabilities found (OSV.dev) in detected libraries"))
    else:
        story.append(P("- Vulnerability check not available"))
    for name, ver in sorted(libs.items())[:40]:
        story.append(P(f"- {name} {ver}"))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Evidence: permissions", styles["Heading3"]))
    for p in r["permissions"]:
        story.append(P("- " + p))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Evidence: exported components", styles["Heading3"]))
    for kind, name in r["exported_components"][:30]:
        story.append(P(f"- {kind}: {name}"))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        f'Evidence: URLs (first 30 of {len(r["urls"])})', styles["Heading3"]))
    for u in r["urls"][:30]:
        story.append(P("- " + u))

    doc.build(story)
    return buf.getvalue()