import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()


def vt_lookup(sha256):
    key = os.environ.get("VT_API_KEY", "").strip().strip('"').strip("'")
    if not key:
        return {"status": "no_key"}
    try:
        resp = None
        for attempt in range(2):
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": key},
                timeout=15,
            )
            if resp.status_code == 429 and attempt == 0:
                time.sleep(20)  # rate limit: thoda ruk ke dobara
                continue
            break

        if resp.status_code == 404:
            return {"status": "not_found"}
        if resp.status_code == 429:
            return {"status": "rate_limited"}
        if resp.status_code != 200:
            return {"status": "error", "message": f"HTTP {resp.status_code}"}

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "status": "found",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}