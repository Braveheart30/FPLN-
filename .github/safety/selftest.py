#!/usr/bin/env python3
"""FPLN built-in test (BIT): runs the real app in a real browser against a private copy of the site and
checks every safety layer. The app is not told it is being tested: it reads the same signal files and
runs the same code it runs for cadets. Only this script knows the orders are a test.

Usage: python3 .github/safety/selftest.py [--root .] [--out results.json] [--chrome /path/to/chrome]
Needs: pip install playwright && python3 -m playwright install chromium (or --chrome)
Exit code 1 if any check fails.
"""
import argparse, functools, hashlib, http.server, json, os, shutil, socketserver, subprocess, sys, tempfile, threading, time, datetime

ap = argparse.ArgumentParser()
ap.add_argument("--root", default=".")
ap.add_argument("--out", default="")
ap.add_argument("--chrome", default=os.environ.get("FPLN_CHROME", ""))
A = ap.parse_args()
REPO = os.path.abspath(A.root)
CTL = os.path.join(REPO, ".github", "safety", "control.py")
TMP = tempfile.mkdtemp(prefix="fpln-bit-")
SITE = os.path.join(TMP, "FPLN-")
os.makedirs(SITE)
for f in ["index.html", "sw.js", "version.json", "control.json", "manifest.webmanifest", "favicon.ico"]:
    shutil.copy(os.path.join(REPO, f), SITE)
shutil.copytree(os.path.join(REPO, "icons"), os.path.join(SITE, "icons"))
if os.path.isdir(os.path.join(REPO, "vendor")): shutil.copytree(os.path.join(REPO, "vendor"), os.path.join(SITE, "vendor"))
if os.path.isdir(os.path.join(REPO, "range")): shutil.copytree(os.path.join(REPO, "range"), os.path.join(SITE, "range"))
# start from a clean signal, whatever the live one says
subprocess.run([sys.executable, CTL, "restore", "--root", SITE], capture_output=True)
subprocess.run([sys.executable, CTL, "switches", "--off", "none", "--root", SITE], capture_output=True)
subprocess.run([sys.executable, CTL, "clear-banner", "--root", SITE], capture_output=True)

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def end_headers(self):
        self.send_header("Cache-Control", "no-store"); super().end_headers()
srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=TMP))
srv.daemon_threads = True
PORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://localhost:%d/FPLN-/" % PORT

def sig(*a): return subprocess.run([sys.executable, CTL, *a, "--root", SITE, "--by", "selftest"], capture_output=True, text=True).stdout.strip()
RES = []
def check(group, name, cond, detail=""):
    RES.append({"group": group, "name": name, "pass": bool(cond), "detail": str(detail)[:120]})
    print(("PASS " if cond else "FAIL ") + group + " · " + name + ((" (" + str(detail)[:80] + ")") if detail else ""))

PROBE = """async (u) => { const fr = document.getElementById('fClock'); const w = fr && fr.contentWindow;
  const f = (w && w.fetch) ? w.fetch.bind(w) : fetch;
  try { await f(u, {mode:'no-cors'}); return 'sent'; } catch(e) { return String(e && e.message || e); } }"""

from playwright.sync_api import sync_playwright
def route(ctx):
    ctx.route("https://braveheart30.github.io/FPLN-/*", lambda r: r.fulfill(path=os.path.join(SITE, r.request.url.split("/FPLN-/")[1].split("?")[0].split("#")[0])))
def nudge(page, expect_reload=True):
    if expect_reload:
        try:
            with page.expect_navigation(timeout=15000): page.evaluate("dispatchEvent(new Event('online'))")
        except Exception: pass
    else:
        page.evaluate("dispatchEvent(new Event('online'))")
    page.wait_for_load_state("domcontentloaded"); time.sleep(3)
def locked(page): return page.evaluate("!!document.getElementById('fplnLocked')")

started = time.time()
with sync_playwright() as p:
    kw = {"args": ["--no-sandbox"]}
    if A.chrome: kw["executable_path"] = A.chrome
    b = p.chromium.launch(**kw)
    ctx = b.new_context(); route(ctx)
    page = ctx.new_page(); errs = []
    page.on("pageerror", lambda e: errs.append(str(e)))
    page.goto(URL); time.sleep(4)
    page.evaluate("localStorage.setItem('fpln:clock', JSON.stringify({v:3,tasks:[{id:'bit1',t:'BIT TASK'}]})); localStorage.setItem('other:site','keep')")
    G = "Normal"
    check(G, "App opens unlocked", page.evaluate("!window.FPLN_LOCKED") and not locked(page))
    check(G, "Planner page loads", page.evaluate("(document.getElementById('fClock').srcdoc||'').length > 1000"))
    check(G, "Guard armed inside planner", page.evaluate("!!document.getElementById('fClock').contentWindow.__fplnArmed"))
    check(G, "Safety row in Privacy & security", page.evaluate("!!(window.FPLN_SAFE && window.FPLN_SAFE.row().t)"))
    page.reload(); time.sleep(3)
    check(G, "Service worker in control", page.evaluate("!!navigator.serviceWorker.controller"))
    rd = page.evaluate("""() => new Promise(res => { const fr = document.getElementById('fClock').contentWindow, doc = fr.document; let n = 0, out = {};
      ['vendor/xlsx-0.20.3.full.min.js', 'vendor/mammoth-1.11.0.browser.min.js'].forEach(src => { const s = doc.createElement('script'); s.src = src;
        s.onload = s.onerror = () => { if (++n === 2) res({xlsx: fr.XLSX && fr.XLSX.version, mammoth: !!(fr.mammoth && fr.mammoth.extractRawText)}); }; doc.head.appendChild(s); }); setTimeout(() => res(out), 8000); })""")
    check(G, "Patched file readers load from FPLN's own site", rd.get("xlsx") == "0.20.3" and rd.get("mammoth"), rd)
    xs = page.evaluate("""() => { const X = document.getElementById('fClock').contentWindow.XLSX; const wb = X.utils.book_new(); X.utils.book_append_sheet(wb, X.utils.aoa_to_sheet([['Task','Due'],['WPR 2','2026-11-10']]), 'S');
      const buf = X.write(wb, {type:'array', bookType:'xlsx'}); const back = X.read(buf, {type:'array'}); return X.utils.sheet_to_csv(back.Sheets.S); }""")
    check(G, "Spreadsheet reader works", "WPR 2" in xs, xs[:40])
    page.evaluate("window.FPLN_SAFE && window.FPLN_SAFE.monitor()"); time.sleep(1.5)
    ev = page.evaluate("window.FPLN_MONITOR ? window.FPLN_MONITOR.events() : []")
    check(G, "Live monitor opens and records", page.evaluate("!!document.getElementById('fplnMon') && !document.getElementById('fplnMon').hidden") and any(e["k"] == "signal" for e in ev) and any(e["k"] == "boot" for e in ev), len(ev))
    check(G, "Monitor records no content", "BIT TASK" not in json.dumps(ev) and "BIT TASK" not in (page.evaluate("localStorage.getItem('fpln:rec')") or ""))
    page.evaluate("document.getElementById('fplnMon').hidden = true")

    G = "Pause"
    sig("freeze", "--msg", "BIT pause"); nudge(page)
    check(G, "Pause screen shown", locked(page))
    check(G, "Message shown", "BIT pause" in page.inner_text("#fplnLocked"))
    check(G, "Planner not loaded", page.evaluate("!(document.getElementById('fClock').srcdoc)"))
    check(G, "Data kept", "BIT TASK" in (page.evaluate("localStorage.getItem('fpln:clock')") or ""))
    r = page.evaluate(PROBE, "https://api.open-meteo.com/v1/forecast?bit=1"); check(G, "Outside request refused", r != "sent", r)
    check(G, "Browser lock (CSP) active", page.evaluate("!!document.querySelector('meta[http-equiv=Content-Security-Policy]')"))
    check(G, "Pop-up links refused", page.evaluate("window.open('https://www.google.com/') === null"))
    page.evaluate("localStorage.setItem('fpln:dash','changed')"); check(G, "App can't rewrite its data", page.evaluate("localStorage.getItem('fpln:dash')") != "changed")
    ctx.set_offline(True); page.reload(); time.sleep(2)
    check(G, "Stays paused offline after restart", locked(page))
    ctx.set_offline(False)
    st = page.evaluate("caches.open('fpln-ctl').then(c=>c.match('state')).then(r=>r&&r.json())")
    check(G, "Service worker holds the pause", st and st.get("state") == "freeze", st and st.get("state"))

    G = "Restore"
    sig("restore"); nudge(page); time.sleep(1)
    check(G, "Pause screen gone", not locked(page) and page.evaluate("!window.FPLN_LOCKED"))
    check(G, "Data still there", "BIT TASK" in (page.evaluate("localStorage.getItem('fpln:clock')") or ""))

    G = "Switches"
    sig("switches", "--off", "weather,feedback"); nudge(page)
    r = page.evaluate(PROBE, "https://api.open-meteo.com/v1/forecast?bit=2"); check(G, "Weather refused", "FPLN" in r, r)
    r = page.evaluate(PROBE, "https://docs.google.com/forms/bit"); check(G, "Feedback refused", "FPLN" in r, r)
    r = page.evaluate(PROBE, "https://fonts.googleapis.com/css2?family=Inter"); check(G, "Fonts still allowed", "FPLN" not in r, r)
    sig("banner", "--msg", "BIT banner"); nudge(page, False)
    shown = False
    for _ in range(12):
        shown = "BIT banner" in (page.evaluate("(document.getElementById('fplnBanner')||{}).textContent") or "")
        if shown: break
        page.evaluate("dispatchEvent(new Event('online'))"); time.sleep(1)
    check(G, "Banner shown", shown)
    sig("switches", "--off", "none"); sig("clear-banner"); nudge(page)

    G = "Uniform"
    home = lambda: [f for f in page.frames if f.evaluate("() => !!document.getElementById('uodBlurb')")][0]
    day = page.evaluate("(() => { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); })()")
    sig("uod", "--date", day, "--text", "ACU under Level 5 with black gloves"); nudge(page, False)
    got = ""
    for _ in range(15):
        try: got = home().evaluate("() => document.getElementById('uodBlurb').textContent + ' | ' + document.getElementById('uodSrc').textContent + ' | ' + [...document.querySelectorAll('[data-slot]')].map(b => b.textContent).join(',')")
        except Exception: got = ""
        if "Level 5" in got and "command" in got.lower(): break
        page.evaluate("dispatchEvent(new Event('online'))"); time.sleep(1)
    check(G, "Posted uniform reaches the cadet", "ACU under Level 5 with black gloves" in got and "command" in got.lower(), got[:110])
    check(G, "Cadet wears the posted gear", "Level 5" in got.split("|")[-1] and "Black gloves" in got.split("|")[-1], got.split("|")[-1][:110])
    sig("uod", "--date", day, "--k", "acu", "--text", "<img src=x onerror=alert(1)>ACU <b>bold</b>"); nudge(page, False)
    for _ in range(15):
        try: got = home().evaluate("() => document.getElementById('uodBlurb').textContent")
        except Exception: got = ""
        if "bold" in got: break
        page.evaluate("dispatchEvent(new Event('online'))"); time.sleep(1)
    imgs = home().evaluate("() => document.querySelectorAll('.uod img').length + document.getElementById('uodBlurb').children.length + document.getElementById('uodSrc').querySelectorAll('img').length")
    check(G, "Uniform text can't carry markup", "bold" in got and "<" not in got and imgs == 0, got[:80])
    sig("clear-uod", "--date", day); nudge(page, False)
    for _ in range(15):
        try: hid = home().evaluate("() => document.getElementById('uodSrc').hidden")
        except Exception: hid = False
        if hid: break
        page.evaluate("dispatchEvent(new Event('online'))"); time.sleep(1)
    check(G, "Removing the uniform takes it off", hid)

    G = "Test group"
    token = "bit-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:28]
    h = hashlib.sha256(token.encode()).hexdigest()[:24]
    page.goto(URL + "#ring=" + token); time.sleep(4)
    hs = page.evaluate("location.hash"); check(G, "Enrollment is silent (link cleared)", "ring" not in hs and not locked(page), hs)
    check(G, "Device joined the group", page.evaluate("localStorage.getItem('fpln:ring')") == h)
    other = b.new_context(); route(other); op = other.new_page(); op.goto(URL); time.sleep(4)
    sig("freeze", "--ring", h, "--msg", "BIT group pause")
    nudge(page); op.evaluate("dispatchEvent(new Event('online'))"); time.sleep(4)
    check(G, "Group device paused like a real order", locked(page) and "BIT group pause" in page.inner_text("#fplnLocked"))
    check(G, "Pause screen identical to a real one", "test" not in page.inner_text("#fplnLocked").lower())
    check(G, "Devices outside the group unaffected", not locked(op))
    sig("restore", "--ring", h); nudge(page)
    check(G, "Group restored", not locked(page))
    other.close()

    G = "Erase"
    sig("erase", "--msg", "BIT shutdown"); nudge(page); time.sleep(1)
    keys = page.evaluate("Object.keys(localStorage)")
    left = [k for k in keys if k.startswith("fpln") and k not in ("fpln:lock", "fpln:ring")]
    check(G, "FPLN data erased", not left, left)
    check(G, "Other sites' data untouched", "other:site" in keys)
    check(G, "Shutdown screen shown", locked(page) and "shut down" in page.inner_text("#fplnLocked"))
    cn = page.evaluate("caches.keys()"); check(G, "Offline copy removed", not [c for c in cn if c.startswith("fpln-") and c != "fpln-ctl"], cn)
    sig("restore"); nudge(page); time.sleep(1)
    check(G, "Restore after erase opens fresh", page.evaluate("!window.FPLN_LOCKED && (document.getElementById('fClock').srcdoc||'').length > 1000"))

    G = "Shutdown site"
    ctx2 = b.new_context(); route(ctx2); p2 = ctx2.new_page()
    p2.goto(URL); time.sleep(4); p2.reload(); time.sleep(3)
    p2.evaluate("localStorage.setItem('fpln:clock','DATA'); localStorage.setItem('other','keep')")
    saved = {f: open(os.path.join(SITE, f), "rb").read() for f in ["index.html", "sw.js"]}
    for f in ["index.html", "sw.js"]: shutil.copy(os.path.join(REPO, ".github", "safety", "tombstone", f), os.path.join(SITE, f))
    sig("erase", "--msg", "BIT site shutdown")
    p2.reload(); time.sleep(5)
    k2 = p2.evaluate("Object.keys(localStorage)")
    check(G, "Installed copy erased by shutdown page", "fpln:clock" not in k2 and "other" in k2, k2)
    check(G, "Worker removed", p2.evaluate("navigator.serviceWorker.getRegistrations().then(r=>r.length)") == 0)
    for f, d in saved.items(): open(os.path.join(SITE, f), "wb").write(d)
    sig("restore"); ctx2.close()

    G = "Test range"
    if os.path.isdir(os.path.join(SITE, "range")):
        ctx3 = b.new_context(); route(ctx3); p3 = ctx3.new_page()
        p3.goto(URL); time.sleep(4); p3.reload(); time.sleep(3)
        p3.evaluate("localStorage.setItem('fpln:clock', JSON.stringify({v:3,tasks:[{id:'mine',t:'OWNER REAL TASK'}]}))")
        p3.goto(URL + "range/?autorun=1&fast=1"); t1 = time.time(); txt = ""
        while time.time() - t1 < 240:
            time.sleep(2); txt = p3.inner_text("#now")
            if txt.startswith(("DONE", "STOPPED", "CAN'T")): break
        fails = p3.evaluate("Array.from(document.querySelectorAll('#rows div')).filter(d=>/FAIL/.test(d.lastChild.textContent)).map(d=>d.firstChild.textContent)")
        npass = p3.evaluate("Array.from(document.querySelectorAll('#rows div')).filter(d=>/PASS/.test(d.lastChild.textContent)).length")
        check(G, "Test range runs every scenario", txt.startswith("DONE") and npass >= 40, "%d passed" % npass)
        check(G, "Every live test passes", txt.startswith("DONE") and not fails, "; ".join(fails)[:110])
        p3.goto(URL); time.sleep(2)
        check(G, "Range never touches the owner's real data", "OWNER REAL TASK" in (p3.evaluate("localStorage.getItem('fpln:clock')") or "") and not p3.evaluate("!!document.getElementById('fplnLocked')"))
        ctx3.close()

    check("Normal", "No script errors from the guard", not [e for e in errs if "fpln" in e.lower()], errs[:2])
    b.close()
srv.shutdown(); shutil.rmtree(TMP, ignore_errors=True)

n = sum(1 for r in RES if r["pass"])
out = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "passed": n, "total": len(RES),
       "result": "Pass" if n == len(RES) else "Fail", "seconds": round(time.time() - started), "checks": RES}
print("\nFPLN BIT: %d/%d passed in %ds" % (n, len(RES), out["seconds"]))
if A.out:
    with open(A.out, "w") as f: json.dump(out, f, indent=1)
sys.exit(0 if n == len(RES) else 1)
