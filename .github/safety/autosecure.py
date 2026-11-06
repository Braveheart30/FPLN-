#!/usr/bin/env python3
"""FPLN auto-secure, fleet side: turns failing tests into automatic, reversible defenses.

Reads the latest test results and decides:
  - A confirmed failure that maps to a feature (Eric, Canvas, file readers, Feedback) switches that
    feature off for every cadet, the same way the owner's feature switches do.
  - When the tests for that feature pass again, auto-secure turns it back on.
  - An actively exploited browser bug (CISA KEV, last 7 days, Chrome/Edge/Safari/Firefox) puts up an
    "update your browser" banner, removed again after 14 days.
  - Anything that doesn't map to a feature is reported only.
It never pauses or erases FPLN, never changes code, and never overrides the owner: if the owner turns a
feature back on after auto-secure switched it off, auto-secure leaves it on until a new failure appears.
State and history live in .github/safety/autosecure.json; switch changes go through control.py with the
order clock, so a newer order from the owner always wins.

Usage:
  autosecure.py decide --adversary adv.json --threat tw.json [--confirm adv2.json] [--root .] [--apply]
  autosecure.py set --enabled on|off | --device on|off | --reset-devices
  autosecure.py status
  autosecure.py selftest
"""
import argparse, copy, datetime, json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FEATURE_OF_ATTACK = {"A1": "eric", "A2": "eric", "A13": "eric", "A15": "eric", "A16": "eric", "A20": "eric", "A22": "eric",
                     "A4": "canvas", "A14": "canvas", "A18": "canvas", "A7": "libs", "A10": "feedback"}
FEATURE_OF_LIB = {"pdfjs-dist": "libs", "mammoth": "libs", "xlsx": "libs", "@mlc-ai/web-llm": "eric"}
FEATURE_OF_SURFACE = {"File import": "libs", "Eric": "eric", "Canvas": "canvas", "Feedback": "feedback"}
NAMES = {"eric": "Eric", "canvas": "Canvas", "libs": "File readers", "feedback": "Feedback"}
BROWSERS = [("chrom", "Chrome"), ("edge", "Edge"), ("webkit", "Safari"), ("safari", "Safari"), ("firefox", "Firefox"), ("v8", "Chrome")]

def now_ms(): return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
def iso(ms=None): return datetime.datetime.fromtimestamp((ms or now_ms()) / 1000, datetime.timezone.utc).isoformat(timespec="seconds")
def load(p, d):
    try:
        with open(p, encoding="utf-8") as f: return json.load(f)
    except Exception: return copy.deepcopy(d)
def save(p, d):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(d, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)

DEFAULT = {"v": 1, "enabled": True, "device": True, "applied": {}, "banner": None, "overridden": {}, "history": []}

def failures(adv, tw, confirm):
    """feature -> sorted list of failing test ids (confirmed when a confirm run is given)."""
    out = {}
    def add(f, tid): out.setdefault(f, set()).add(tid)
    conf = None
    if confirm is not None:
        conf = {a["id"] for a in confirm.get("attacks", []) if a.get("verdict") in ("BREACHED", "BROKEN")}
    for a in (adv or {}).get("attacks", []):
        if a.get("verdict") != "BREACHED": continue
        if conf is not None and a["id"] not in conf: continue      # failed once, passed on the re-run: not confirmed
        f = FEATURE_OF_ATTACK.get(a["id"])
        if f: add(f, a["id"])
    for l in (tw or {}).get("libs", []):
        for v in l.get("vulns", []):
            if v.get("status") == "OPEN" and FEATURE_OF_LIB.get(l["name"]): add(FEATURE_OF_LIB[l["name"]], v["id"])
    for t in (tw or {}).get("threats", []):
        if t.get("status") == "EXPOSED" and FEATURE_OF_SURFACE.get(t.get("surface", "").split(" (")[0]): add(FEATURE_OF_SURFACE[t["surface"].split(" (")[0]], t["id"])
    return {k: sorted(v) for k, v in out.items()}

def unmapped(adv):
    return sorted(a["id"] for a in (adv or {}).get("attacks", []) if a.get("verdict") in ("BREACHED", "BROKEN") and a["id"] not in FEATURE_OF_ATTACK)

def browser_advisory(tw, days=7):
    cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).date().isoformat()
    names = []
    for a in (tw or {}).get("advisories", []):
        if a.get("added", "") < cutoff: continue
        p = a.get("product", "").lower()
        for k, nm in BROWSERS:
            if k in p and nm not in names: names.append(nm)
    return names

def control(root, *args):
    r = subprocess.run([sys.executable, os.path.join(HERE, "control.py"), *args, "--root", root, "--by", "autosecure", "--at", str(now_ms())], capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()

def decide(st, ctl, fails, advis, unm):
    """Pure decision: returns (new_state, new_off_list or None, banner action or None, events)."""
    st = copy.deepcopy(st); ev = []; t = now_ms()
    cur_off = set(ctl.get("off") or [])
    owner_off = cur_off - set(st["applied"].keys())
    # owner override: a feature auto-secure switched off is back on, and the owner's switch order is newer
    owner_at = ctl.get("at_off") or 0
    for f, a in list(st["applied"].items()):
        if f not in cur_off and (ctl.get("by") != "autosecure" or owner_at > a.get("at", 0)):
            st["overridden"][f] = a.get("sig", []); del st["applied"][f]
            ev.append({"at": iso(t), "what": "owner turned %s back on; auto-secure will leave it on until a new failure" % NAMES.get(f, f)})
    if not st["enabled"]:
        return st, None, None, ev + ([{"at": iso(t), "what": "auto-secure is off; no action"}] if fails else [])
    want = set(owner_off)
    for f, ids in fails.items():
        if st["overridden"].get(f) == ids: continue               # the owner already overrode this exact failure
        st["overridden"].pop(f, None)
        if f not in st["applied"]:
            st["applied"][f] = {"at": t, "sig": ids}
            ev.append({"at": iso(t), "what": "switched off %s for every cadet: %s" % (NAMES.get(f, f), ", ".join(ids))})
        else: st["applied"][f]["sig"] = ids
        want.add(f)
    for f in list(st["applied"].keys()):
        if f not in fails:
            ev.append({"at": iso(t), "what": "tests for %s pass again; turned it back on" % NAMES.get(f, f)}); del st["applied"][f]
        else: want.add(f)
    for f in list(st["overridden"].keys()):
        if f not in fails: del st["overridden"][f]
    new_off = sorted(want) if want != cur_off else None
    bn = None
    if advis and not (ctl.get("banner") and ctl.get("by") != "autosecure" and not st.get("banner")):
        text = "Update %s today: there's a security bug attackers are using right now. Restart the browser after updating." % " and ".join(advis)
        if not st.get("banner") or st["banner"].get("text") != text:
            bn = ("set", text); st["banner"] = {"text": text, "at": t}; ev.append({"at": iso(t), "what": "browser advisory banner: " + ", ".join(advis)})
    elif st["applied"] and not st.get("banner") and not (ctl.get("banner") and ctl.get("by") not in ("autosecure", "auto-secure")):
        names = " and ".join(NAMES.get(f, f) for f in sorted(st["applied"]))
        text = "%s is off for a safety check. Your planner is safe on this device." % names
        bn = ("set", text); st["banner"] = {"text": text, "at": t, "kind": "contain"}; ev.append({"at": iso(t), "what": "safety-check banner: " + names})
    elif st.get("banner") and st["banner"].get("kind") == "contain":
        if not st["applied"]: bn = ("clear", ""); st["banner"] = None; ev.append({"at": iso(t), "what": "every feature is back on; safety-check banner removed"})
    elif st.get("banner") and (not advis or t - st["banner"]["at"] > 14 * 864e5):
        bn = ("clear", ""); st["banner"] = None; ev.append({"at": iso(t), "what": "browser advisory banner removed"})
    for u in unm: ev.append({"at": iso(t), "what": "reported only (no feature to switch off): " + u})
    return st, new_off, bn, ev

def details(adv, conf):
    """what each failing attack or check found, so the issue explains itself (names and addresses only, no secrets)"""
    out = []
    for run, r in (("first run", adv), ("re-run", conf)):
        for a in (r or {}).get("attacks", []):
            if a.get("verdict") in ("BREACHED", "BROKEN", "ERROR"):
                out.append("\n**%s %s** (%s, %s)\n" % (a["id"], a.get("name", ""), a["verdict"], run))
                out += ["- %s" % str(x)[:240] for x in (a.get("findings") or [])[:5] + (a.get("notes") or [])[:8]]
    return ("\n#### Details\n" + "\n".join(out) + "\n") if out else ""

def cmd_decide(A):
    root = os.path.abspath(A.root); sp = os.path.join(HERE, "autosecure.json")
    st = load(sp, DEFAULT); ctl = load(os.path.join(root, "control.json"), {})
    adv = load(A.adversary, None) if A.adversary else None; tw = load(A.threat, None) if A.threat else None
    conf = load(A.confirm, None) if A.confirm else None
    fails = failures(adv, tw, conf); advis = browser_advisory(tw); unm = unmapped(adv)
    st2, new_off, bn, ev = decide(st, ctl, fails, advis, unm)
    print(json.dumps({"failures": fails, "advisory": advis, "unmapped": unm, "switch_off": new_off, "banner": bn, "events": ev}, indent=1))
    # a failure with no feature to switch off is noted once, not on every run (repeats made a commit and an issue every 6 hours)
    prev = set(((st.get("last") or {}).get("unmapped")) or [])
    ev = [e for e in ev if not (e["what"].startswith("reported only") and e["what"].split(": ")[-1] in prev)]
    new_last = {"failures": fails, "advisory": advis, "unmapped": unm}
    material = new_off is not None or bool(bn) or bool(ev) or new_last != (st.get("last") or {})
    if A.apply and not material:
        print("auto-secure: nothing changed; state file left as is")
        if A.summary:
            with open(A.summary, "w") as f: f.write("### FPLN auto-secure\n\nNothing changed this run.\n" + details(adv, conf))
        return 0
    if A.apply:
        if new_off is not None:
            code, out = control(root, "switches", "--off", ",".join(new_off) or "none"); print(out)
            if code == 3: ev.append({"at": iso(), "what": "a newer owner order was live; auto-secure didn't change switches"})
        if bn:
            code, out = control(root, *(["banner", "--msg", bn[1], "--level", "info" if (st2.get("banner") or {}).get("kind") == "contain" else "warn"] if bn[0] == "set" else ["clear-banner"])); print(out)
        st2["history"] = (st2.get("history", []) + ev)[-60:]; st2["checked"] = iso()
        st2["last"] = {"failures": fails, "advisory": advis, "unmapped": unm}
        save(sp, st2)
        if A.summary:
            with open(A.summary, "w") as f:
                f.write("### FPLN auto-secure\n\n")
                f.write("Auto-secure is **%s**. Switched off by auto-secure: %s\n\n" % ("on" if st2["enabled"] else "off", ", ".join(NAMES.get(k, k) for k in st2["applied"]) or "nothing"))
                for e in ev: f.write("- %s\n" % e["what"])
                f.write(details(adv, conf))
    return 0

def cmd_set(A):
    root = os.path.abspath(A.root); sp = os.path.join(HERE, "autosecure.json"); st = load(sp, DEFAULT)
    if A.enabled: st["enabled"] = A.enabled == "on"
    if A.device or A.reset_devices:
        cp = os.path.join(root, "control.json"); ctl = load(cp, {})
        a = ctl.get("autosecure") or {"device": True}
        if A.device: a["device"] = A.device == "on"; st["device"] = a["device"]
        if A.reset_devices: a["reset"] = "R-" + str(now_ms())
        ctl["autosecure"] = a; save(cp, ctl)
    st["history"] = (st.get("history", []) + [{"at": iso(), "what": "owner: " + " ".join(x for x in [A.enabled and "fleet " + A.enabled, A.device and "devices " + A.device, A.reset_devices and "reset devices"] if x)}])[-60:]
    save(sp, st); print(json.dumps({k: st[k] for k in ("enabled", "device", "applied")}))
    return 0

def cmd_status(A):
    st = load(os.path.join(HERE, "autosecure.json"), DEFAULT); print(json.dumps(st, indent=1)); return 0

def cmd_selftest(A):
    """Checks the decision rules without touching anything real."""
    ok = []; tw0 = {"libs": [], "threats": [], "advisories": []}
    def check(name, cond): ok.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name)
    adv_bad = {"attacks": [{"id": "A1", "verdict": "BREACHED"}, {"id": "A3", "verdict": "BREACHED"}, {"id": "A5", "verdict": "RESISTED"}]}
    st, off, bn, ev = decide(DEFAULT, {"off": ["weather"]}, failures(adv_bad, tw0, adv_bad), [], unmapped(adv_bad))
    check("confirmed Eric breach switches Eric off and keeps the owner's switches", off == ["eric", "weather"] and "eric" in st["applied"])
    check("a breach with no feature is reported only", any("A3" in e["what"] for e in ev))
    st2, off2, _, _ = decide(DEFAULT, {"off": []}, failures(adv_bad, tw0, {"attacks": []}), [], [])
    check("a breach that passes on the re-run does nothing", off2 is None and not st2["applied"])
    st3, off3, _, ev3 = decide(st, {"off": ["eric", "weather"], "by": "autosecure", "at_off": 5}, {}, [], [])
    check("Eric comes back on when its tests pass, owner's switch stays", off3 == ["weather"] and not st3["applied"])
    st4, off4, _, _ = decide(st, {"off": ["weather"], "by": "command-center", "at_off": now_ms() + 1000}, failures(adv_bad, tw0, adv_bad), [], [])
    check("owner override is respected for the same failure", off4 is None and "eric" in st4["overridden"])
    adv_new = {"attacks": [{"id": "A1", "verdict": "BREACHED"}, {"id": "A15", "verdict": "BREACHED"}]}
    st5, off5, _, _ = decide(st4, {"off": ["weather"], "by": "command-center", "at_off": now_ms()}, failures(adv_new, tw0, adv_new), [], [])
    check("a new failure after an override switches it off again", off5 == ["eric", "weather"])
    dis = dict(DEFAULT, enabled=False)
    _, off6, _, _ = decide(dis, {"off": []}, failures(adv_bad, tw0, adv_bad), [], [])
    check("when auto-secure is off it changes nothing", off6 is None)
    tw_lib = {"libs": [{"name": "pdfjs-dist", "vulns": [{"id": "GHSA-x", "status": "OPEN"}]}], "threats": [], "advisories": []}
    _, off7, _, _ = decide(DEFAULT, {"off": []}, failures(None, tw_lib, None), [], [])
    check("an open vulnerability in the PDF reader switches off file readers", off7 == ["libs"])
    today = datetime.date.today().isoformat()
    tw_kev = {"libs": [], "threats": [], "advisories": [{"id": "CVE-X", "product": "Google Chromium V8", "added": today}]}
    st8, _, bn8, _ = decide(DEFAULT, {"off": []}, {}, browser_advisory(tw_kev), [])
    check("an exploited browser bug sets the update banner", bn8 and bn8[0] == "set" and "Chrome" in bn8[1])
    _, _, bn9, _ = decide(st8, {"off": [], "by": "autosecure"}, {}, [], [])
    check("the banner is cleared when the advisory ages out", bn9 and bn9[0] == "clear")
    stc = json.loads(json.dumps(DEFAULT)); stc["applied"] = {"eric": {"at": 0, "sig": ["A2"]}}; stc["banner"] = {"text": "check", "at": 0, "kind": "contain"}
    _, _, bnc, _ = decide(stc, {"off": ["eric"], "banner": {"text": "check"}, "by": "auto-secure"}, {"eric": ["A2"]}, [], [])
    check("a safety-check banner stays while its feature is still off", bnc is None)
    _, offc, bnc2, _ = decide(stc, {"off": ["eric"], "banner": {"text": "check"}, "by": "auto-secure"}, {}, [], [])
    check("and is removed when the feature comes back", bnc2 == ("clear", "") and offc == [])
    _, _, bnn, _ = decide(json.loads(json.dumps(DEFAULT)), {"off": [], "banner": None, "by": "command-center"}, {"canvas": ["A4"]}, [], [])
    check("switching a feature off tells cadets why, calmly", bnn and bnn[0] == "set" and "safety check" in bnn[1])
    _, _, bno, _ = decide(json.loads(json.dumps(DEFAULT)), {"off": [], "banner": {"text": "Owner message"}, "by": "command-center"}, {"canvas": ["A4"]}, [], [])
    check("but never over the owner's banner", bno is None)
    _, _, bn10, _ = decide(DEFAULT, {"off": [], "banner": {"text": "Owner message"}, "by": "command-center"}, {}, browser_advisory(tw_kev), [])
    check("an owner's own banner is never replaced", bn10 is None)
    # end to end against a scratch copy of the signal files
    d = tempfile.mkdtemp(prefix="fpln-auto-")
    try:
        for f in ("control.json", "version.json"): shutil.copy(os.path.join(HERE, "..", "..", f), d)
        code, out = control(d, "switches", "--off", "eric")
        c = load(os.path.join(d, "control.json"), {})
        check("control.py applies an auto-secure switch with the order clock", code == 0 and c.get("off") == ["eric"] and c.get("by") == "autosecure")
    finally: shutil.rmtree(d, ignore_errors=True)
    bad = [n for n, c in ok if not c]
    print("\nauto-secure selftest: %d/%d passed" % (len(ok) - len(bad), len(ok)))
    return 1 if bad else 0

ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
d = sub.add_parser("decide"); d.add_argument("--adversary"); d.add_argument("--threat"); d.add_argument("--confirm"); d.add_argument("--root", default="."); d.add_argument("--apply", action="store_true"); d.add_argument("--summary")
s = sub.add_parser("set"); s.add_argument("--enabled", choices=["on", "off"]); s.add_argument("--device", choices=["on", "off"]); s.add_argument("--reset-devices", action="store_true"); s.add_argument("--root", default=".")
sub.add_parser("status"); sub.add_parser("selftest")
A = ap.parse_args()
sys.exit({"decide": cmd_decide, "set": cmd_set, "status": cmd_status, "selftest": cmd_selftest}[A.cmd](A))
