import sys, re, json, hashlib, ipaddress
from urllib.parse import urlparse
from loguru import logger
logger.remove()  # androguard ke logs band

from androguard.core.apk import APK
from androguard.core.dex import DEX
from intel import vt_lookup
from libs import detect_libraries, check_vulnerabilities

NS = "{http://schemas.android.com/apk/res/android}"

# permission -> (points, reason)
RISKY_PERMS = {
    "android.permission.READ_SMS": (15, "Reads SMS"),
    "android.permission.SEND_SMS": (15, "Sends SMS"),
    "android.permission.RECEIVE_SMS": (10, "Intercepts incoming SMS"),
    "android.permission.READ_CONTACTS": (8, "Reads contacts"),
    "android.permission.READ_CALL_LOG": (8, "Reads call log"),
    "android.permission.RECORD_AUDIO": (8, "Records audio"),
    "android.permission.ACCESS_FINE_LOCATION": (5, "Precise location"),
    "android.permission.SYSTEM_ALERT_WINDOW": (10, "Draws over other apps"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (15, "Accessibility service abuse"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (10, "Can install other apps"),
    "android.permission.REQUEST_DELETE_PACKAGES": (5, "Can delete other apps"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (5, "Full storage access"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (3, "Starts on boot"),
    "android.permission.QUERY_ALL_PACKAGES": (3, "Lists all installed apps"),
}

# evasion / suspicious code strings -> (points, reason)
EVASION = {
    "dalvik/system/DexClassLoader": (10, "Dynamic code loading (DexClassLoader)"),
    "isDebuggerConnected": (5, "Anti-debugging check"),
    "goldfish": (5, "Emulator detection string"),
    "ranchu": (5, "Emulator detection string"),
    "Genymotion": (5, "Emulator detection string"),
    "qemu": (5, "Emulator detection string"),
    "Runtime.getRuntime": (3, "Runtime command execution API"),
}

URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
IGNORE = ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org")


def file_hashes(path):
    data = open(path, "rb").read()
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


def exported_components(apk):
    result = []
    manifest = apk.get_android_manifest_xml()
    app = manifest.find("application")
    for tag in ("activity", "service", "receiver", "provider"):
        for el in app.findall(tag):
            name = el.get(NS + "name")
            exported = el.get(NS + "exported")
            has_filter = el.find("intent-filter") is not None
            if exported == "true" or (exported is None and has_filter):
                result.append((tag, name))
    return result


def is_public_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast
                    or ip.is_reserved or ip.is_link_local or ip.is_unspecified)
    except ValueError:
        return False


URL_BYTES_RE = re.compile(rb"https?://[^\s\"'<>\\\x00-\x1f\x7f-\xff]+")
EVASION_BYTES = {k.encode(): v for k, v in EVASION.items()}


def scan_strings(apk):
    urls, ips, evasion_hits = set(), set(), {}
    for dex_bytes in apk.get_all_dex():
        for m in URL_BYTES_RE.findall(dex_bytes):
            u = m.decode("utf-8", "ignore")
            if any(i in u for i in IGNORE):
                continue
            urls.add(u)
            try:
                host = urlparse(u).hostname
            except ValueError:
                host = None
            if host and is_public_ip(host):
                ips.add(host)
        for key, val in EVASION_BYTES.items():
            if key in dex_bytes:
                evasion_hits[key.decode()] = val
    return urls, ips, evasion_hits


def certificate_info(apk):
    try:
        cert = apk.get_certificates()[0]
        return {
            "subject": cert.subject.human_friendly,
            "issuer": cert.issuer.human_friendly,
            "sha256": cert.sha256_fingerprint,
        }
    except Exception:
        return None


def analyze_apk(path):
    md5, sha256 = file_hashes(path)
    apk = APK(path)

    permissions = apk.get_permissions()
    exported = exported_components(apk)
    urls, ips, evasion_hits = scan_strings(apk)
    cert = certificate_info(apk)
    libs = detect_libraries(apk)
    vuln = check_vulnerabilities(libs)

    score = 0
    reasons = []
    for p in permissions:
        if p in RISKY_PERMS:
            pts, why = RISKY_PERMS[p]
            score += pts
            reasons.append(f"+{pts}: {why} ({p.split('.')[-1]})")
    for key, (pts, why) in evasion_hits.items():
        score += pts
        reasons.append(f"+{pts}: {why}")
    if ips:
        score += 10
        reasons.append(f"+10: Hardcoded public IP addresses found ({len(ips)})")
    if len(exported) > 5:
        score += 5
        reasons.append(f"+5: Many exported components ({len(exported)})")

    vulnerable = vuln.get("vulnerable", [])
    if vulnerable:
        pts = min(3 * len(vulnerable), 9)
        score += pts
        reasons.append(f"+{pts}: {len(vulnerable)} library(ies) with known vulnerabilities (OSV.dev)")

    vt = vt_lookup(sha256)
    if vt["status"] == "found":
        if vt["malicious"] >= 5:
            score += 40
            reasons.append(f"+40: Flagged malicious by {vt['malicious']} VirusTotal engines")
        elif vt["malicious"] >= 1:
            score += 15
            reasons.append(f"+15: Flagged by {vt['malicious']} VirusTotal engine(s)")

    score = min(score, 100)
    level = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH"

    return {
        "file": path, "md5": md5, "sha256": sha256,
        "package": apk.get_package(), "app_name": apk.get_app_name(),
        "version": apk.get_androidversion_name(),
        "permissions": permissions, "exported_components": exported,
        "urls": sorted(urls), "ips": sorted(ips),
        "certificate": cert, "score": score, "level": level,
        "reasons": reasons, "virustotal": vt,
        "libraries": libs, "vuln": vuln,
    }


if __name__ == "__main__":
    r = analyze_apk(sys.argv[1])
    print(f"{r['package']}  ->  RISK SCORE: {r['score']}/100 ({r['level']})")
    for x in r["reasons"]:
        print("  ", x)
    print("VirusTotal:", r["virustotal"])
    print("Libraries detected:", len(r["libraries"]))
    print("Vulnerability check:", r["vuln"].get("status"),
          "| vulnerable libs:", len(r["vuln"].get("vulnerable", [])))
    with open("report.json", "w") as f:
        json.dump(r, f, indent=2)