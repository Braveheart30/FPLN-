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
  control.py uod --text "ACU under Level 5 with black gloves" [--date YYYY-MM-DD] [--k acu --sel OUTER=ecwcs,HANDS=gloves]
                                       post the uniform of the day (default today, New York); without --k the words are read by
                                       uodparse.js, the same reader the app and the Command Center use
  control.py clear-uod [--date YYYY-MM-DD]
  control.py status                    print the current signal

Add --ring HASH to any of these to address only the devices in one test group (the 24-character
group code from the Command Center). Group orders live in control.json under "rings"; the app obeys
them exactly as it obeys everyone-orders, so it can't tell a drill from the real thing.
restore --ring HASH removes that group's orders.
"""
import re, subprocess
import argparse, json, os, sys, datetime

FEATURES = ["eric", "feedback", "weather", "canvas", "fonts", "libs", "links"]
ap = argparse.ArgumentParser()
ap.add_argument("action", choices=["freeze", "erase", "restore", "switches", "banner", "clear-banner", "uod", "clear-uod", "status"])
ap.add_argument("--text", default="")
ap.add_argument("--date", default="")
ap.add_argument("--k", default="")
ap.add_argument("--sel", default="")
ap.add_argument("--msg", default="")
ap.add_argument("--off", default="")
ap.add_argument("--level", default="info", choices=["info", "warn"])
ap.add_argument("--root", default=".")
ap.add_argument("--by", default="manual")
ap.add_argument("--ring", default="")
ap.add_argument("--at", type=int, default=0, help="when the owner gave the order (epoch ms); an older order never overwrites a newer one")
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

HERE = os.path.dirname(os.path.abspath(__file__))
def node(*args):
    r = subprocess.run(["node", os.path.join(HERE, "uodparse.js")] + list(args), capture_output=True, text=True, timeout=20)
    return json.loads(r.stdout or "{}")
def uod_date():
    if A.date:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", A.date): sys.exit("--date must be YYYY-MM-DD")
        return A.date
    try:
        from zoneinfo import ZoneInfo
        return datetime.datetime.now(ZoneInfo("America/New_York")).strftime("%Y-%m-%d")
    except Exception:
        return (now - datetime.timedelta(hours=5)).strftime("%Y-%m-%d")
def uod_order():
    """the order to post: uniform key, gear per slot and the line cadets read; everything checked against the app's catalog"""
    cat = json.loads(subprocess.run(["node", "-e", "process.stdout.write(JSON.stringify(require(process.argv[1]).CATALOG))", os.path.join(HERE, "uodparse.js")],
                                    capture_output=True, text=True, timeout=20).stdout)
    text = clean(A.text, 200)
    if A.k:
        k = A.k.strip().lower(); sel = {}
        for pair in [x for x in A.sel.split(",") if x.strip()]:
            sep = "=" if "=" in pair else ":" if ":" in pair else None
            if not sep: sys.exit("--sel takes SLOT=gear pairs, e.g. OUTER=ecwcs,HANDS=gloves")
            sl, v = [x.strip() for x in pair.split(sep, 1)]; sel[sl.upper()] = v.lower()
    else:
        if not text: sys.exit("--text is required for uod (or give --k and --sel)")
        r = node(text); k, sel = r.get("k", ""), r.get("sel", {})
        if not k: sys.exit("No uniform found in: %r. Start with ACU, As for Class, White over Gray, Dress Gray, Full Dress or APFU." % text)
        if not r.get("unknown"): text = r.get("text") or text
    if k not in cat: sys.exit("Unknown uniform %r. Use: %s" % (k, ", ".join(cat)))
    for sl, v in sel.items():
        if sl not in cat[k] or v not in cat[k][sl]: sys.exit("%s has no %s choice %r. Choices: %s" % (k, sl, v, ", ".join(cat[k].get(sl, [])) or "none"))
    return {"id": "U-" + stamp, "k": k, "sel": sel, "text": re.sub(r"[<>\x00-\x1f]", " ", text)[:200], "at": A.at or int(now.timestamp() * 1000), "by": clean(A.by, 20)}
def uod_apply(holder):
    """post or clear one day; keeps at most 10 days and drops days before yesterday. Returns False if a newer order for that day is live."""
    d = uod_date(); m = holder.get("uod") if isinstance(holder.get("uod"), dict) else {}
    if A.at and isinstance(m.get(d), dict) and int(m[d].get("at") or 0) > A.at:
        print("Refused: a newer uniform order for %s is already live." % d); return False
    if A.action == "uod": m[d] = uod_order()
    else: m.pop(d, None)
    floor = (datetime.date.fromisoformat(uod_date() if not A.date else d) - datetime.timedelta(days=1)).isoformat() if A.action == "uod" else "0000-00-00"
    m = {x: m[x] for x in sorted(m)[-10:] if x >= min(floor, d)}
    if m: holder["uod"] = m
    else: holder.pop("uod", None)
    print("FPLN uniform %s: %s" % (d, m[d]["text"] if d in m else "cleared")); return True

if A.action == "status":
    print(json.dumps({"control": ctl, "version_kill": ver.get("kill")}, indent=2)); sys.exit(0)

KIND = {"freeze": "at_kill", "erase": "at_kill", "restore": "at_kill", "switches": "at_off", "banner": "at_banner", "clear-banner": "at_banner"}.get(A.action)
def too_old(holder):
    """True if a newer order of the same kind is already in place (orders sent seconds apart can finish out of order)."""
    if not A.at or not KIND: return False
    have = holder.get(KIND) if isinstance(holder, dict) else None
    if isinstance(have, int) and have > A.at:
        print("Refused: a newer %s order (given %s) is already live; this one was given %s." % (KIND[3:], have, A.at)); return True
    return False

RING = A.ring.strip().lower()
if RING and not re.fullmatch(r"[0-9a-f]{24}", RING):
    sys.exit("--ring must be the 24-character group code")
if RING and A.action != "status":
    rings = ctl.get("rings") if isinstance(ctl.get("rings"), dict) else {}
    g = rings.get(RING) or {"kill": {"state": "none", "id": "", "msg": ""}, "off": [], "banner": None}
    if too_old(g): sys.exit(3)
    if A.at and KIND: g[KIND] = A.at
    if A.action in ("freeze", "erase"): g["kill"] = {"state": A.action, "id": "K-" + stamp, "msg": clean(A.msg)}
    elif A.action == "restore": g["kill"] = {"state": "none", "id": "R-" + stamp, "msg": ""}
    elif A.action == "switches":
        raw = [x.strip().lower() for x in A.off.split(",") if x.strip()]
        if raw == ["none"]: raw = []
        bad = [x for x in raw if x not in FEATURES]
        if bad: sys.exit("Unknown feature(s): " + ", ".join(bad))
        g["off"] = sorted(set(raw))
    elif A.action == "banner":
        if not A.msg.strip(): sys.exit("--msg is required for a banner")
        g["banner"] = {"id": "B-" + stamp, "text": clean(A.msg, 300), "level": A.level}
    elif A.action == "clear-banner": g["banner"] = None
    elif A.action in ("uod", "clear-uod"):
        if not uod_apply(g): sys.exit(3)
    if g["kill"]["state"] == "none" and not g["off"] and not g.get("banner") and not g.get("uod") and not A.at: rings.pop(RING, None)
    else: rings[RING] = g
    ctl["rings"] = rings
    ctl["rev"] = "group-" + A.action + "-" + stamp
    ctl["updated"] = now.isoformat(timespec="seconds")
    ctl["by"] = clean(A.by, 40)
    tmp = C + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(ctl, f, indent=2, ensure_ascii=False)
    json.load(open(tmp, encoding="utf-8")); os.replace(tmp, C)
    print("FPLN group %s: %s" % (RING[:6], json.dumps(rings.get(RING)) if RING in rings else "no orders"))
    sys.exit(0)

if too_old(ctl): sys.exit(3)
if A.at and KIND: ctl[KIND] = A.at
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
elif A.action in ("uod", "clear-uod"):
    if not uod_apply(ctl): sys.exit(3)

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
