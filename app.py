import os
import re
import json
import html
from typing import List
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse, Response
from analyze import analyze_apk, RISKY_PERMS
from report_pdf import build_pdf

app = FastAPI(title="APK Analyzer")
os.makedirs("uploads", exist_ok=True)
os.makedirs("reports", exist_ok=True)

esc = html.escape

STYLE = """
<style>
 body{font-family:Arial,sans-serif;max-width:1100px;margin:40px auto;padding:0 16px;background:#0f172a;color:#e2e8f0}
 h1{color:#38bdf8}
 .card{background:#1e293b;border-radius:10px;padding:20px;margin:16px 0}
 .score{font-size:48px;font-weight:bold}
 .LOW{color:#22c55e}.MEDIUM{color:#f59e0b}.HIGH{color:#ef4444}
 .LOWbg{background:#22c55e}.MEDIUMbg{background:#f59e0b}.HIGHbg{background:#ef4444}
 .bar{background:#334155;border-radius:4px;height:8px;margin-top:6px}
 .fill{height:8px;border-radius:4px}
 table{width:100%;border-collapse:collapse}
 td,th{padding:8px 6px;border-bottom:1px solid #334155;word-break:break-all;vertical-align:top;text-align:left}
 td:first-child{width:150px;color:#94a3b8}
 .scroll{overflow-x:auto}
 button,input[type=file]{padding:10px;margin-top:10px}
 a{color:#38bdf8}
 li{margin:4px 0}
 summary{cursor:pointer;color:#38bdf8}
 .btn{display:inline-block;background:#38bdf8;color:#0f172a;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:bold}
</style>
"""


def vt_text(vt):
    if vt.get("status") == "found":
        total = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
        return f'{vt["malicious"]} malicious / {total} engines'
    return "n/a (" + esc(str(vt.get("status"))) + ")"


def vt_card(vt):
    if vt["status"] == "found":
        return (
            '<div class="card"><h3>VirusTotal</h3>'
            f'<p>{vt["malicious"]} engines: malicious, {vt["suspicious"]}: suspicious, '
            f'{vt["harmless"] + vt["undetected"]}: clean/undetected.</p>'
            f'<a href="{vt["link"]}" target="_blank">Open on VirusTotal</a></div>'
        )
    msgs = {
        "not_found": "This file hash is not known to VirusTotal.",
        "no_key": "VirusTotal API key is not set.",
        "rate_limited": "Rate limit reached, try again in a minute.",
    }
    fallback = "Lookup failed: " + esc(str(vt.get("message", "")))
    return ('<div class="card"><h3>VirusTotal</h3><p>'
            + msgs.get(vt["status"], fallback) + "</p></div>")


def libs_card(r):
    libs = r.get("libraries", {})
    vuln = r.get("vuln", {})
    if not libs:
        return ('<div class="card"><h3>Third-party libraries</h3>'
                "<p>No library version info found in this APK.</p></div>")
    if vuln.get("status") == "error":
        note = "<p>Vulnerability lookup failed: " + esc(str(vuln.get("message", ""))) + "</p>"
    elif vuln.get("vulnerable"):
        items = ""
        for v in vuln["vulnerable"]:
            links = ", ".join(
                f'<a href="https://osv.dev/vulnerability/{esc(i)}" target="_blank">{esc(i)}</a>'
                for i in v["ids"][:5])
            items += (f"<li><b>{esc(v['name'])}</b> {esc(v['version'])}: "
                      f"{v['count']} advisories ({links})</li>")
        note = (f'<p class="HIGH">{len(vuln["vulnerable"])} vulnerable libraries found:</p>'
                f"<ul>{items}</ul>")
    else:
        note = ('<p class="LOW">No known vulnerabilities found (OSV.dev) '
                "in the detected libraries.</p>")
    rows = "".join(f"<li>{esc(n)} {esc(v)}</li>" for n, v in sorted(libs.items())[:60])
    return (f'<div class="card"><h3>Third-party libraries ({len(libs)} detected)</h3>{note}'
            f"<details><summary>Show detected libraries</summary><ul>{rows}</ul></details></div>")


def render_detail(r):
    reasons = "".join(f"<li>{esc(x)}</li>" for x in r["reasons"]) or "<li>No risky indicators found</li>"
    urls = "".join(f"<li>{esc(u)}</li>" for u in r["urls"][:20]) or "<li>None</li>"
    ips = ", ".join(esc(i) for i in r["ips"]) or "None"
    cert = esc(r["certificate"]["subject"]) if r["certificate"] else "N/A"
    return f"""
    <h1>APK Analyzer</h1>
    <div class="card">
      <div class="score {r['level']}">{r['score']}/100 &nbsp; {r['level']}</div>
      <h3>Why this score?</h3>
      <ul>{reasons}</ul>
      <a class="btn" href="/report/{r['sha256']}">Download PDF report</a>
    </div>
    <div class="card">
      <h3>App details</h3>
      <table>
        <tr><td>App name</td><td>{esc(str(r['app_name']))}</td></tr>
        <tr><td>Package</td><td>{esc(r['package'])}</td></tr>
        <tr><td>Version</td><td>{esc(str(r['version']))}</td></tr>
        <tr><td>MD5</td><td>{r['md5']}</td></tr>
        <tr><td>SHA256</td><td>{r['sha256']}</td></tr>
        <tr><td>Certificate</td><td>{cert}</td></tr>
        <tr><td>Permissions</td><td>{len(r['permissions'])}</td></tr>
        <tr><td>Exported components</td><td>{len(r['exported_components'])}</td></tr>
        <tr><td>Public IPs</td><td>{ips}</td></tr>
      </table>
    </div>
    {vt_card(r['virustotal'])}
    {libs_card(r)}
    <div class="card">
      <h3>URLs found (first 20 of {len(r['urls'])})</h3>
      <ul>{urls}</ul>
    </div>
    <a href="/">Analyze another APK</a>
    """


def render_compare(results, errors):
    out = "<h1>APK Comparison</h1>"
    for name, msg in errors:
        out += (f'<div class="card">Could not analyze <b>{esc(name)}</b>: '
                f"<small>{esc(msg)}</small></div>")
    if not results:
        return out + "<a href='/'>Back</a>"

    def tr(label, cells):
        return ("<tr><td>" + label + "</td>"
                + "".join("<td>" + c + "</td>" for c in cells) + "</tr>")

    head = "<tr><th></th>" + "".join(
        f"<th>{esc(r['upload_name'])}</th>" for r in results) + "</tr>"

    rows = [
        tr("Risk score", [
            f'<b class="{r["level"]}">{r["score"]}/100 {r["level"]}</b>'
            f'<div class="bar"><div class="fill {r["level"]}bg" style="width:{r["score"]}%"></div></div>'
            for r in results]),
        tr("Package", [esc(r["package"]) for r in results]),
        tr("Version", [esc(str(r["version"])) for r in results]),
        tr("Permissions", [str(len(r["permissions"])) for r in results]),
        tr("Risky permissions", [
            str(len([p for p in r["permissions"] if p in RISKY_PERMS])) for r in results]),
        tr("Exported components", [str(len(r["exported_components"])) for r in results]),
        tr("URLs found", [str(len(r["urls"])) for r in results]),
        tr("Public IPs", [str(len(r["ips"])) for r in results]),
        tr("Libraries detected", [str(len(r.get("libraries", {}))) for r in results]),
        tr("Vulnerable libraries", [
            str(len(r.get("vuln", {}).get("vulnerable", []))) for r in results]),
        tr("VirusTotal", [vt_text(r["virustotal"]) for r in results]),
        tr("Certificate", [
            esc(r["certificate"]["subject"]) if r["certificate"] else "N/A" for r in results]),
        tr("SHA256", [r["sha256"][:16] + "..." for r in results]),
        tr("Open", [
            f'<a href="/result/{r["sha256"]}">Details</a> | '
            f'<a href="/report/{r["sha256"]}">PDF</a>' for r in results]),
    ]
    out += ('<div class="card scroll"><table>' + head + "".join(rows)
            + "</table></div>")

    # same signing certificate wale APKs
    groups = {}
    for r in results:
        if r["certificate"]:
            groups.setdefault(r["certificate"]["sha256"], []).append(r["upload_name"])
    shared = [names for names in groups.values() if len(names) > 1]
    if shared:
        items = "".join(
            "<li>" + ", ".join(esc(n) for n in names) + "</li>" for names in shared)
        out += ('<div class="card"><h3>Same signing certificate</h3>'
                "<p>These APKs are signed with the same key: same developer, "
                "or a re-signed copy that reuses the key.</p>"
                f"<ul>{items}</ul></div>")

    # permission comparison
    if len(results) > 1:
        perm_sets = {r["upload_name"]: set(r["permissions"]) for r in results}
        common = set.intersection(*perm_sets.values())
        items = ""
        for name, perms in perm_sets.items():
            others = set().union(*[s for n, s in perm_sets.items() if n != name])
            only = sorted(perms - others)
            shown = ", ".join(esc(p.split(".")[-1]) for p in only[:15]) or "none"
            items += f"<p><b>{esc(name)}</b> only ({len(only)}): {shown}</p>"
        out += ('<div class="card"><h3>Permission comparison</h3>'
                f"<p>Common to all APKs: {len(common)} permissions</p>{items}</div>")

    return out + '<a href="/">Analyze more APKs</a>'


@app.get("/", response_class=HTMLResponse)
def home():
    return STYLE + """
    <h1>APK Analyzer</h1>
    <div class="card">
      <p>1. Choose an APK. Repeat to add more APKs to the list.</p>
      <input type="file" id="picker" accept=".apk">
      <ul id="list"></ul>
      <button type="button" id="clear">Clear list</button>

      <form id="f" action="/analyze" method="post" enctype="multipart/form-data">
        <input type="file" name="files" id="real" multiple hidden>
        <p>2. Click Analyze when the list is ready.</p>
        <button type="submit">Analyze</button>
      </form>
    </div>
    <script>
      const dt = new DataTransfer();
      const picker = document.getElementById('picker');
      const real = document.getElementById('real');
      const list = document.getElementById('list');

      function render() {
        list.innerHTML = '';
        for (const f of dt.files) {
          const li = document.createElement('li');
          li.textContent = f.name;
          list.appendChild(li);
        }
      }

      picker.addEventListener('change', () => {
        for (const f of picker.files) dt.items.add(f);
        real.files = dt.files;
        render();
        picker.value = '';
      });

      document.getElementById('clear').addEventListener('click', () => {
        dt.items.clear();
        real.files = dt.files;
        render();
      });

      document.getElementById('f').addEventListener('submit', (e) => {
        if (dt.files.length === 0) {
          e.preventDefault();
          alert('Please add at least one APK first.');
        }
      });
    </script>
    """


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(files: List[UploadFile] = File(...)):
    results, errors = [], []
    for file in files:
        name = os.path.basename(file.filename or "upload.apk")
        save_path = os.path.join("uploads", name)
        with open(save_path, "wb") as f:
            f.write(await file.read())
        try:
            r = analyze_apk(save_path)
            r["upload_name"] = name
            with open(os.path.join("reports", r["sha256"] + ".json"), "w") as f:
                json.dump(r, f)
            results.append(r)
        except Exception as e:
            errors.append((name, str(e)))

    if len(results) == 1 and not errors:
        return STYLE + render_detail(results[0])
    return STYLE + render_compare(results, errors)


def load_report(sha256):
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        return None
    path = os.path.join("reports", sha256 + ".json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


@app.get("/result/{sha256}", response_class=HTMLResponse)
def result(sha256: str):
    r = load_report(sha256)
    if not r:
        return HTMLResponse("Report not found", status_code=404)
    return STYLE + render_detail(r)


@app.get("/report/{sha256}")
def report(sha256: str):
    r = load_report(sha256)
    if not r:
        return HTMLResponse("Report not found", status_code=404)
    pdf = build_pdf(r)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{sha256[:8]}.pdf"'},
    )