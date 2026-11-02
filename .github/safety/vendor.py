#!/usr/bin/env python3
"""Download FPLN's self-hosted libraries into vendor/, check them, and pin their SHA-256 in vendor/manifest.json.
Usage: python3 .github/safety/vendor.py [--root .] [--verify]
  --verify  don't download; only check that every file in vendor/ matches manifest.json (the release scan runs this)
"""
import argparse, hashlib, json, os, re, sys, urllib.request
ap = argparse.ArgumentParser(); ap.add_argument("--root", default="."); ap.add_argument("--verify", action="store_true"); A = ap.parse_args()
R = os.path.abspath(A.root); V = os.path.join(R, "vendor"); M = os.path.join(V, "manifest.json")
def sha(b): return hashlib.sha256(b).hexdigest()
if A.verify:
    man = json.load(open(M)) if os.path.exists(M) else {"files": {}}
    bad = []
    for f in sorted(os.listdir(V)) if os.path.isdir(V) else []:
        if f == "manifest.json": continue
        want = man["files"].get(f, {}).get("sha256")
        got = sha(open(os.path.join(V, f), "rb").read())
        if want != got: bad.append("%s: %s" % (f, "not in manifest" if not want else "changed since it was pinned"))
    for f in man["files"]:
        if not os.path.exists(os.path.join(V, f)): bad.append(f + ": missing")
    print("\n".join(bad) if bad else "vendor: all %d files match their pinned hashes" % len(man["files"]))
    sys.exit(1 if bad else 0)
src = json.load(open(os.path.join(R, ".github", "safety", "vendor_sources.json")))
os.makedirs(V, exist_ok=True)
man = {"note": "SHA-256 of every self-hosted library. Written by vendor.py; checked by the release scan.", "files": {}}
for lib in src["libs"]:
    req = urllib.request.Request(lib["url"], headers={"User-Agent": "FPLN-vendor"})
    body = urllib.request.urlopen(req, timeout=60).read()
    if len(body) < 10000 or len(body) > 14_000_000: sys.exit("%s: unexpected size %d" % (lib["name"], len(body)))
    if lib["expect"].encode() not in body: sys.exit("%s: expected text %r not found; refusing" % (lib["name"], lib["expect"]))
    if b"<html" in body[:2000].lower(): sys.exit("%s: got a web page, not a script" % lib["name"])
    ext = sorted(set(re.findall(rb'(?:from|import)\s*\(?\s*["\'](/npm/[^"\']+|https?://[^"\']+)["\']', body)))
    if ext: print("%s: imports outside code, not self-contained: %s" % (lib["name"], b", ".join(ext[:5]).decode())); continue
    open(os.path.join(V, lib["file"]), "wb").write(body)
    man["files"][lib["file"]] = {"name": lib["name"], "ecosystem": lib["ecosystem"], "version": lib["version"], "sha256": sha(body), "bytes": len(body), "source": lib["url"]}
    print("%s %s: %d bytes, sha256 %s" % (lib["name"], lib["version"], len(body), sha(body)[:16]))
json.dump(man, open(M, "w"), indent=2)
