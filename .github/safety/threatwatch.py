#!/usr/bin/env python3
"""FPLN threat watch (test tier 1): checks FPLN against the newest known threats.

  1. Every library FPLN loads (from its code and vendor/manifest.json) is looked up in OSV.dev, the
     open vulnerability database, so newly published vulnerabilities show up the day they're public.
  2. Every entry in threats.json (the vaccine list) is checked: fixed library versions, required code
     defenses. Red-team entries are listed here and run by redteam.py.
  3. Policy consistency: the app's allowlist, the worker's allowlist and the browser policy agree;
     outside scripts are pinned to exact versions; self-hosted libraries match their pinned hashes.
  4. Browser advisories: actively exploited browser bugs added to CISA's Known Exploited
     Vulnerabilities list in the last 30 days (FPLN can't patch the browser, but can tell cadets to update).

Usage: python3 .github/safety/threatwatch.py [--root .] [--out threatwatch.json] [--offline]
Exit 1 if a library has an unmitigated vulnerability, a vaccine check fails, or the policies disagree.
"""
import argparse, datetime, json, os, re, subprocess, sys, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--root", default="."); ap.add_argument("--out", default=""); ap.add_argument("--offline", action="store_true")
A = ap.parse_args()
R = os.path.abspath(A.root)
HERE = os.path.join(R, ".github", "safety")
html = open(os.path.join(R, "index.html"), encoding="utf-8").read()
sw = open(os.path.join(R, "sw.js"), encoding="utf-8").read()
TH = json.load(open(os.path.join(HERE, "threats.json")))
NOW = datetime.datetime.now(datetime.timezone.utc)
OSV = "https://api.osv.dev/v1/query"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def vt(v): return tuple(int(x) for x in re.findall(r"\d+", v)[:4])
def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "User-Agent": "FPLN-threatwatch"})
    return json.load(urllib.request.urlopen(req, timeout=30))
def get(url):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "FPLN-threatwatch"}), timeout=60))

# ---- libraries in use ----
libs = {}
for m in re.finditer(r"cdn\.jsdelivr\.net/npm/((?:@[\w.-]+/)?[\w.-]+)@([0-9][\w.-]*)", html):
    libs[(m.group(1), m.group(2))] = {"name": m.group(1), "version": m.group(2), "from": "jsDelivr", "vulns": []}
man_p = os.path.join(R, "vendor", "manifest.json")
if os.path.exists(man_p):
    for f, v in json.load(open(man_p))["files"].items():
        if ("vendor/" + f) in html:
            libs[(v["name"], v["version"])] = {"name": v["name"], "version": v["version"], "from": "self-hosted", "vulns": []}
libs = sorted(libs.values(), key=lambda x: x["name"])

def assert_ok(t):
    miss = [p for p in t.get("present", []) if p not in html]
    bad = [p for p in t.get("absent", []) if p in html]
    return not miss and not bad, ("missing: " + ", ".join(miss) if miss else "") + (" found: " + ", ".join(bad) if bad else "")

mitig = {}
for t in TH["threats"]:
    if t["type"] == "code-assert":
        ok, _ = assert_ok(t)
        for v in t.get("mitigates", []): mitig[v] = (ok, t["id"])
    if t["type"] == "dependency":   # a fixed version in use mitigates the advisory even when a database's version range is stale
        have = [l for l in libs if l["name"] == t["pkg"]]
        ok = bool(have) and all(vt(l["version"]) >= vt(t["min"]) for l in have)
        for v in t.get("mitigates", []): mitig[v] = (ok, t["id"])

net = {"osv": None, "kev": None}
if not A.offline:
    for lib in libs:
        try:
            r = post(OSV, {"package": {"name": lib["name"], "ecosystem": "npm"}, "version": lib["version"]}); net["osv"] = True
            for v in r.get("vulns", []):
                ids = [v["id"]] + v.get("aliases", [])
                hit = next((mitig[i] for i in ids if i in mitig), None)
                st = "MITIGATED" if hit and hit[0] else "OPEN"
                lib["vulns"].append({"id": v["id"], "aliases": v.get("aliases", [])[:4], "summary": (v.get("summary") or v.get("details", ""))[:160], "status": st, "by": hit[1] if hit else ""})
        except Exception as e:
            net["osv"] = False; lib["error"] = "OSV unreachable: " + str(e)[:80]

# ---- vaccine list ----
threats = []
for t in TH["threats"]:
    row = {"id": t["id"], "name": t["name"], "type": t["type"], "surface": t.get("surface", ""), "added": t.get("added", ""), "source": t.get("source", "")}
    if t["type"] == "dependency":
        have = [l for l in libs if l["name"] == t["pkg"]]
        if not have: row.update(status="N/A", detail="%s not used" % t["pkg"])
        else:
            low = min(have, key=lambda l: vt(l["version"]))
            ok = vt(low["version"]) >= vt(t["min"])
            row.update(status="PROTECTED" if ok else "EXPOSED", detail="%s %s (needs %s or later)" % (t["pkg"], low["version"], t["min"]))
    elif t["type"] == "code-assert":
        ok, d = assert_ok(t); row.update(status="PROTECTED" if ok else "EXPOSED", detail=d or "defense present in code")
    elif t["type"] in ("exfil", "api-absent"):
        row.update(status="RED TEAM", detail="Checked by the red team (" + (t.get("technique") or t.get("api")) + ")")
    elif t["type"] == "advisory":
        row.update(status="ADVISORY", detail=t.get("note", ""))
    else:
        row.update(status="NO TEST YET", detail=t.get("note", "Needs a test written"))
    threats.append(row)

# ---- policy consistency ----
policy = []
def pc(name, ok, detail=""): policy.append({"check": name, "pass": bool(ok), "detail": detail})
gm = re.search(r"var DATA_OK = \[([^\]]+)\]", html); sm = re.search(r"const DATA_OK = \[([^\]]+)\]", sw)
gset = set(re.findall(r'"([^"]+)"', gm.group(1))) if gm else set(); sset = set(re.findall(r"'([^']+)'", sm.group(1))) if sm else set()
pc("App and worker allowlists match", gset and gset == sset, ", ".join(sorted(gset ^ sset)) or "%d services" % len(gset))
csp_hosts = set(h.lstrip("*.") for h in re.findall(r"https://([\w*.-]+)", " ".join(re.findall(r"connect-src[^;\"]+", html))))
extra = sorted(h for h in csp_hosts if not any(h == d or h.endswith("." + d) for d in gset))
pc("Browser policy allows nothing the allowlist doesn't", not extra, ", ".join(extra) or "consistent")
unpinned = sorted(set(re.findall(r"cdn\.jsdelivr\.net/npm/((?:@[\w.-]+/)?[\w.-]+)(?=/|\")(?!@)", html)))
pc("Outside scripts pinned to exact versions", not unpinned, ", ".join(unpinned) or "all pinned")
pc("No unencrypted script or data addresses", not re.search(r"src=\\?[\"']http://|fetch\(\\?[\"']http://", html), "")
pc("Safety guard present in the app", 'id="fpln-safety"' in html)
pc("Worker enforces the browser policy", "Content-Security-Policy" in sw and "PAUSED_PAGE" in sw)
vr = subprocess.run([sys.executable, os.path.join(HERE, "vendor.py"), "--root", R, "--verify"], capture_output=True, text=True)
pc("Self-hosted libraries match pinned hashes", vr.returncode == 0, vr.stdout.strip()[:120])

# ---- browser advisories ----
adv = []
if not A.offline:
    try:
        k = get(KEV); net["kev"] = True
        cutoff = (NOW - datetime.timedelta(days=30)).date().isoformat()
        for v in k.get("vulnerabilities", []):
            vp, pr = v.get("vendorProject", ""), v.get("product", "")
            if v.get("dateAdded", "") >= cutoff and re.search(r"chrom|edge|webkit|safari|firefox|v8|skia|angle|webgpu|dawn", (vp + " " + pr).lower()):
                adv.append({"id": v["cveID"], "product": vp + " " + pr, "name": v.get("vulnerabilityName", "")[:120], "added": v["dateAdded"]})
    except Exception as e:
        net["kev"] = False

open_v = [(l["name"], v["id"]) for l in libs for v in l["vulns"] if v["status"] == "OPEN"]
exposed = [t["id"] for t in threats if t["status"] == "EXPOSED"]
failing = [p["check"] for p in policy if not p["pass"]]
result = "Fail" if open_v or exposed or failing else ("Incomplete" if net["osv"] is False else "Pass")
out = {"at": NOW.isoformat(timespec="seconds"), "tier": "T1", "result": result, "network": net,
       "summary": {"libraries": len(libs), "open_vulns": len(open_v), "mitigated": sum(1 for l in libs for v in l["vulns"] if v["status"] == "MITIGATED"),
                   "threats": len(threats), "exposed": len(exposed), "policy_fail": len(failing), "advisories": len(adv)},
       "libs": libs, "threats": threats, "policy": policy, "advisories": adv, "list_updated": TH.get("updated", ""), "list_by": TH.get("by", "")}
for l in libs:
    print("%-28s %-10s %s" % (l["name"] + " " + l["version"], l["from"], (", ".join(v["id"] + " " + v["status"] for v in l["vulns"]) or ("no known vulnerabilities" if net["osv"] else l.get("error", "not checked")))))
for t in threats: print("%-12s %-15s %s" % (t["status"], t["id"], t["name"]))
for p in policy: print("%s  %s %s" % ("PASS" if p["pass"] else "FAIL", p["check"], ("(" + p["detail"] + ")") if p["detail"] else ""))
for a in adv: print("ADVISORY  %s %s (added %s)" % (a["id"], a["product"], a["added"]))
print("\nFPLN threat watch: %s · %d open vulnerabilities, %d exposed, %d policy failures, %d browser advisories" % (result, len(open_v), len(exposed), len(failing), len(adv)))
if A.out: json.dump(out, open(A.out, "w"), indent=1)
sys.exit(1 if result == "Fail" else 0)
