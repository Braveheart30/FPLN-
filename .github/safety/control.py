#!/usr/bin/env python3
"""FPLN remote control: writes the safety signal that every copy of FPLN reads.

The signal lives in two files at the site root (two separate copies, so one bad edit can't silence it):
  control.json  kill state, switched-off features, broadcast banner
  version.json  same kill state in its "kill" field

Usage (run from the repo root):
  control.py freeze   [--msg TEXT]     pause FPLN everywhere: nothing leaves any device, data kept
  control.py erase    [--msg TEXT]     shut FPLN down and erase FPLN's data on every device that checks in
  control.py restore                   end a freeze or erase; FPLN opens normally again (erased data stays gone)
  control.py switches --off a,b        switch off features: eric, feedback, weather, canvas, fonts, libs, links ("none" = all on)
  control.py banner   --msg TEXT [--level info|warn]
  control.py clear-banner
  control.py status                    print the current signal
"""
import argparse, json, os, sys, datetime

FEATURES = ["eric", "feedback", "weather", "canvas", "fonts", "libs", "links"]
ap = argparse.ArgumentParser()
ap.add_argument("action", choices=["freeze", "erase", "restore", "switches", "banner", "clear-banner", "status"])
ap.add_argument("--msg", default="")
ap.add_argument("--off", default="")
ap.add_argument("--level", default="info", choices=["info", "warn"])
ap.add_argument("--root", default=".")
ap.add_argument("--by", default="manual")
A = ap.parse_args()

C = os.path.join(A.root, "control.json")
V = os.path.join(A.root, "version.json")

def load(p, default):
    try:
        with open(p, encoding="utf-8") as f: return json.load(f)
    except Exception: return default

def clean(t, n=400):
    t = " ".join(str(t).split())
    return t[:n]

now = datetime.datetime.now(datetime.timezone.utc)
stamp = now.strftime("%Y%m%d-%H%M%S")
ctl = load(C, {"v": 1, "kill": {"state": "none", "id": "", "msg": ""}, "off": [], "banner": None})
ver = load(V, None)
if ver is None:
    sys.exit("version.json is missing or unreadable: fix it before changing the signal")

if A.action == "status":
    print(json.dumps({"control": ctl, "version_kill": ver.get("kill")}, indent=2)); sys.exit(0)

if A.action in ("freeze", "erase"):
    ctl["kill"] = {"state": A.action, "id": "K-" + stamp, "msg": clean(A.msg)}
elif A.action == "restore":
    ctl["kill"] = {"state": "none", "id": "R-" + stamp, "msg": ""}
elif A.action == "switches":
    raw = [x.strip().lower() for x in A.off.split(",") if x.strip()]
    if raw == ["none"]: raw = []
    bad = [x for x in raw if x not in FEATURES]
    if bad: sys.exit("Unknown feature(s): %s. Use: %s" % (", ".join(bad), ", ".join(FEATURES)))
    ctl["off"] = sorted(set(raw))
elif A.action == "banner":
    if not A.msg.strip(): sys.exit("--msg is required for a banner")
    ctl["banner"] = {"id": "B-" + stamp, "text": clean(A.msg, 300), "level": A.level}
elif A.action == "clear-banner":
    ctl["banner"] = None

ctl["v"] = 1
ctl["rev"] = A.action + "-" + stamp
ctl["updated"] = now.isoformat(timespec="seconds")
ctl["by"] = clean(A.by, 40)
ver["kill"] = {"state": ctl["kill"]["state"], "id": ctl["kill"].get("id", ""), "msg": ctl["kill"].get("msg", "")}

# both copies must agree before anything is written
assert ver["kill"]["state"] == ctl["kill"]["state"]
for p, d in ((C, ctl), (V, ver)):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(d, f, indent=2 if p == C else None, ensure_ascii=False)
    json.load(open(tmp, encoding="utf-8"))
    os.replace(tmp, p)
print("FPLN signal: kill=%s off=%s banner=%s" % (ctl["kill"]["state"], ",".join(ctl["off"]) or "-", "yes" if ctl.get("banner") else "-"))
