#!/usr/bin/env python3
"""FPLN safety check.

Scans what FPLN publishes for things that must never be public:
  - secrets (API keys, tokens, private keys)
  - personal information (SSNs, DoD IDs, personal emails or phone numbers)
  - CUI markings and military documents
  - new places the app could send data to (every web address must be on the allowlist)
  - files that don't belong on the site (Word, PDF, spreadsheets, databases...)
Exit code 1 means something was found; the release stops and GitHub emails the owner.

Usage: python3 guard.py [--root DIR] [--history] [--private FILE]
  --history  also scan every past commit for secrets (GitHub runs this)
  --private  extra blocklist kept OFF GitHub (owner's own personal details)
"""
import os, re, sys, io, json, zipfile, subprocess, argparse

ap = argparse.ArgumentParser()
ap.add_argument("--root", default=".")
ap.add_argument("--history", action="store_true")
ap.add_argument("--private", default="")
A = ap.parse_args()
ROOT = os.path.abspath(A.root)

# ---------- rules ----------
SECRETS = [
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"),
    ("Canvas access token", r"\b\d{4,5}~[A-Za-z0-9]{40,}\b"),
    ("OpenAI key", r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}"),
    ("AWS key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("Slack token", r"\bxox[abpors]-[A-Za-z0-9-]{10,}"),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("Hard-coded bearer token", r"Bearer [A-Za-z0-9._~+/=-]{24,}"),
    ("Password in code", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
]
PII = [
    ("Social Security number", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ("DoD ID / EDIPI", r"(?i)\b(?:edipi|dod ?id|cac)\D{0,12}\d{10}\b"),
    ("Email address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:com|edu|mil|org|net|gov|us|io)\b"),
    ("Phone number", r"(?<![\d.])(?:\(\d{3}\)\s?|\b\d{3}[-.])\d{3}[-.]\d{4}\b"),
]
CUI = [
    ("CUI marking", r"\bCUI//|\(CUI\)|CONTROLLED UNCLASSIFIED INFORMATION"),
    ("FOUO marking", r"\bFOUO\b|FOR OFFICIAL USE ONLY"),
    ("Classification marking", r"\b(?:SECRET|CONFIDENTIAL)//|\((?:S|C|TS)//"),
    ("Distribution statement", r"DISTRIBUTION STATEMENT [B-F]\b"),
    ("Military order text", r"(?i)\bFRAGORD\s*(?:#|NO\.?)?\s*\d|\bOPORD\s+\d{2,}-\d{2,}|\bTASKORD\s*\d"),
    ("Roster", r"(?i)\b(?:cadet|company|platoon) roster\b.{0,40}\d"),
]
# Public numbers and addresses the app is meant to show (official West Point / vendor contacts).
ALLOW_PHONES = {"315-774-8200","315-774-8300","845-446-4731","845-446-5446","845-446-8749","845-446-8750","845-938-3030",
                "845-938-3590","845-938-4159","845-938-5125","845-957-7895","845-938-4456","845-938-4041","800-275-8777"}
ALLOW_EMAIL = re.compile(r"@(?:users\.noreply\.github\.com)$|^noreply@anthropic\.com$")
# Where the app may connect. DATA = can carry what a cadet types (only with their own key/consent).
HOSTS_DATA = {"api.anthropic.com","generativelanguage.googleapis.com","docs.google.com","api.open-meteo.com"}
HOSTS_LIBS = {"cdn.sheetjs.com","fonts.googleapis.com","fonts.gstatic.com","cdn.jsdelivr.net","cdnjs.cloudflare.com","unpkg.com","esm.run","huggingface.co","raw.githubusercontent.com"}
HOSTS_LINKS = {"aistudio.google.com","corp.commissaries.com","history.army.mil","keller.tricare.mil","tools.usps.com","usma.libcal.com","wanderlog.com",
               "westpoint.edu","www.westpoint.edu","www.google.com","www.ikehall.com","www.openstreetmap.org","www.opentable.com","www.shopmyexchange.com",
               "braveheart30.github.io","github.com","westpoint.instructure.com","www.w3.org","console.anthropic.com","schema.org"}
ALLOWED_HOSTS = HOSTS_DATA | HOSTS_LIBS | HOSTS_LINKS
OK_EXT = {".html",".js",".json",".webmanifest",".png",".ico",".svg",".md",".txt",".zip",".yml",".yaml",".py",".url",".cmd",""}
BAD_EXT = {".docx",".doc",".pdf",".xlsx",".xls",".csv",".pptx",".db",".sqlite",".env",".pem",".key",".p12",".pfx",".bak",".log"}
SKIP_DIRS = {".git"}
SELF = os.path.abspath(__file__)

private = []
if A.private and os.path.exists(A.private):
    for ln in open(A.private, encoding="utf-8"):
        ln = ln.strip()
        if ln and not ln.startswith("#"): private.append(ln)

findings = []
def add(kind, where, what):
    w = what if len(what) < 90 else what[:87] + "..."
    findings.append((kind, where, w))

def mask(s):
    s = str(s)
    return s if len(s) <= 8 else s[:4] + "…" + s[-3:]

def scan_text(where, text, secrets_only=False):
    for name, rx in SECRETS:
        for m in re.finditer(rx, text):
            add("SECRET: "+name, where, mask(m.group(0)))
    if secrets_only: return
    for name, rx in PII:
        for m in re.finditer(rx, text):
            v = m.group(0)
            if name == "Email address":
                if re.search(r"@\d", v) or ALLOW_EMAIL.search(v): continue
            if name == "Phone number":
                n = re.sub(r"\D", "", v)
                if "%s-%s-%s" % (n[:3], n[3:6], n[6:]) in ALLOW_PHONES: continue
            add("PERSONAL: "+name, where, mask(v) if name != "Phone number" else v)
    for name, rx in CUI:
        for m in re.finditer(rx, text):
            add("CUI: "+name, where, text[max(0, m.start()-25):m.end()+25].replace("\n", " "))
    for h in set(re.findall(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)):
        h = h.lower().rstrip(".")
        if h in ALLOWED_HOSTS or h.endswith(".instructure.com") or h.endswith(".github.io"): continue
        if h in ("localhost",) or h.endswith(".test") or h.endswith(".example") or h == "example.com": continue
        add("NEW ADDRESS (could send data somewhere new)", where, h)
    low = text.lower()
    for p in private:
        if p.lower() in low:
            add("PERSONAL: owner's private detail", where, mask(p))

def scan_file(path, rel):
    ext = os.path.splitext(path)[1].lower()
    if ext in BAD_EXT: add("FILE: document or data file on the public site", rel, ext); return
    if ext not in OK_EXT: add("FILE: unexpected file type", rel, ext or "(none)")
    if ext == ".zip":
        try:
            with zipfile.ZipFile(path) as z:
                for n in z.namelist():
                    e2 = os.path.splitext(n)[1].lower()
                    if e2 in BAD_EXT: add("FILE: document inside download", rel+"!"+n, e2)
                    elif e2 in {".txt",".cmd",".url",".html",".md",".json",".js"}:
                        scan_text(rel+"!"+n, z.read(n).decode("utf-8", "replace"))
        except Exception as e: add("FILE: unreadable zip", rel, str(e))
        return
    if ext in {".png",".ico"}: return
    try: text = open(path, encoding="utf-8", errors="replace").read()
    except Exception: return
    vendored = rel.replace(os.sep, "/").startswith("vendor/") and ext == ".js"
    scan_text(rel, text, secrets_only=os.path.abspath(path) == SELF or rel.endswith("guard.py") or vendored)

n = 0
for dp, dns, fns in os.walk(ROOT):
    dns[:] = [d for d in dns if d not in SKIP_DIRS]
    for f in fns:
        p = os.path.join(dp, f); rel = os.path.relpath(p, ROOT); n += 1
        scan_file(p, rel)

if A.history and os.path.isdir(os.path.join(ROOT, ".git")):
    try:
        log = subprocess.run(["git", "-C", ROOT, "log", "-p", "--all", "--no-color", "-U0"], capture_output=True, text=True, timeout=300).stdout
        added = "\n".join(l[1:] for l in log.splitlines() if l.startswith("+") and not l.startswith("+++"))
        before = len(findings)
        scan_text("git history", added, secrets_only=True)
        for i in range(before, len(findings)): findings[i] = (findings[i][0] + " (in an old commit)",) + findings[i][1:]
    except Exception as e:
        add("CHECK: could not read history", ROOT, str(e))

# self-hosted libraries must match the hashes they were pinned with
vp = os.path.join(ROOT, ".github", "safety", "vendor.py")
if os.path.isdir(os.path.join(ROOT, "vendor")) and os.path.exists(vp):
    vr = subprocess.run([sys.executable, vp, "--root", ROOT, "--verify"], capture_output=True, text=True)
    if vr.returncode != 0:
        for ln in vr.stdout.strip().splitlines(): add("FILE: self-hosted library doesn't match its pinned hash", "vendor", ln)

print("FPLN safety check: %d files scanned%s." % (n, ", history included" if A.history else ""))
if not findings:
    print("PASS: no secrets, personal information, CUI or new data destinations found.")
    sys.exit(0)
print("FAIL: %d finding(s)\n" % len(findings))
seen = set()
for k, w, v in findings:
    key = (k, w, v)
    if key in seen: continue
    seen.add(key); print("  [%s] %s: %s" % (k, w, v))
out = os.environ.get("GITHUB_STEP_SUMMARY")
if out:
    with open(out, "a") as f:
        f.write("## FPLN safety check: FAIL\n\n| Finding | Where | Detail |\n|---|---|---|\n")
        for k, w, v in sorted(seen): f.write("| %s | %s | `%s` |\n" % (k, w, v.replace("|", "/")))
sys.exit(1)
