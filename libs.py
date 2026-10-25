import re
import requests

VERSION_OK = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.\-+_]{0,39}$")


def detect_libraries(apk):
    """APK ke META-INF se library naam aur version nikalta hai."""
    libs = {}
    for name in apk.get_files():
        try:
            if name.startswith("META-INF/") and name.endswith(".version"):
                base = name[len("META-INF/"):-len(".version")]
                if "/" in base or "_" not in base:
                    continue
                group, artifact = base.split("_", 1)
                text = apk.get_file(name).decode("utf-8", "ignore").strip()
                version = text.splitlines()[0].strip() if text else ""
                if version and VERSION_OK.match(version):
                    libs[f"{group}:{artifact}"] = version

            elif name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                props = {}
                for line in apk.get_file(name).decode("utf-8", "ignore").splitlines():
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        props[k.strip()] = v.strip()
                g = props.get("groupId")
                a = props.get("artifactId")
                v = props.get("version")
                if g and a and v and VERSION_OK.match(v):
                    libs[f"{g}:{a}"] = v
        except Exception:
            continue
    return libs


def check_vulnerabilities(libs):
    """OSV.dev se pooch ke batata hai kaunsi library vulnerable hai."""
    if not libs:
        return {"status": "ok", "vulnerable": []}

    items = list(libs.items())
    vulnerable = []
    try:
        for start in range(0, len(items), 500):
            chunk = items[start:start + 500]
            queries = [
                {"package": {"name": n, "ecosystem": "Maven"}, "version": v}
                for n, v in chunk
            ]
            resp = requests.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
                timeout=30,
            )
            if resp.status_code != 200:
                return {"status": "error", "message": f"HTTP {resp.status_code}"}
            results = resp.json().get("results", [])
            for (name, version), res in zip(chunk, results):
                vulns = res.get("vulns", [])
                if vulns:
                    vulnerable.append({
                        "name": name,
                        "version": version,
                        "count": len(vulns),
                        "ids": [x["id"] for x in vulns][:10],
                    })
    except Exception as e:
        return {"status": "error", "message": str(e)}

    return {"status": "ok", "vulnerable": vulnerable}