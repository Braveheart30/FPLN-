/* FPLN service worker: newest version on every launch, works offline after the first visit.
   Safety layer 6: reads control.json on its own and, while FPLN is paused or shut down, refuses
   every request to another site at the network layer, even if the page's own code fails. */
const CACHE = 'fpln-202611020430';
const CTL = 'fpln-ctl';
const CORE = ['./', './index.html', './manifest.webmanifest', './favicon.ico', './icons/icon-32.png', './icons/icon-64.png', './icons/icon-192.png', './icons/icon-512.png'];
const FEAT = {
  eric: { h: ['generativelanguage.googleapis.com', 'api.anthropic.com', 'huggingface.co', 'raw.githubusercontent.com'], p: ['/@mlc-ai/'] },
  feedback: { h: ['docs.google.com'] },
  weather: { h: ['api.open-meteo.com'] },
  canvas: { h: ['instructure.com'] },
  fonts: { h: ['fonts.googleapis.com', 'fonts.gstatic.com'] },
  libs: { h: ['cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'esm.run'] }
};
// layer 8: the only outside places FPLN's code loads from or sends to (same list as the app's guard)
const DATA_OK = ['braveheart30.github.io', 'generativelanguage.googleapis.com', 'api.anthropic.com', 'huggingface.co', 'hf.co', 'raw.githubusercontent.com',
  'docs.google.com', 'api.open-meteo.com', 'instructure.com', 'fonts.googleapis.com', 'fonts.gstatic.com', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com', 'esm.run'];
let SAFE = null, lastCheck = 0, RING = '';           // {state, id, off:[]}; RING = this device's group, if any
const ready = caches.open(CTL).then(c => Promise.all([c.match('state'), c.match('ring')])).then(([r, g]) => Promise.all([r ? r.json() : null, g ? g.text() : ''])).then(([s, g]) => { SAFE = s || { state: 'none', off: [] }; RING = g || ''; }).catch(() => { SAFE = { state: 'none', off: [] }; });

function save(s) { SAFE = s; return caches.open(CTL).then(c => c.put('state', new Response(JSON.stringify(s), { headers: { 'content-type': 'application/json' } }))); }
function refresh(force) {
  if (!force && Date.now() - lastCheck < 60000) return Promise.resolve();
  lastCheck = Date.now();
  return fetch('./control.json?sw=' + Date.now(), { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(j => {
    if (!j) return;
    const grp = (RING && j.rings && j.rings[RING]) || null;
    const rank = x => x && x.kill ? ({ freeze: 1, erase: 2 }[x.kill.state] || 0) : 0;
    const src = rank(grp) > rank(j) ? grp : j;
    const k = src.kill && ['freeze', 'erase'].includes(src.kill.state) ? src.kill : { state: 'none' };
    const off = [...new Set([...(Array.isArray(j.off) ? j.off : []), ...(grp && Array.isArray(grp.off) ? grp.off : [])])].filter(x => FEAT[x]);
    const was = SAFE ? SAFE.state : 'none';
    const s = { state: k.state, id: k.id || '', off, at: Date.now() };
    const p = save(s);
    if (k.state === 'erase' && was !== 'erase') {
      // remove the offline copy and any on-phone AI model; keep only the safety state
      return p.then(() => caches.keys()).then(ns => Promise.all(ns.filter(n => (n.startsWith('fpln-') && n !== CTL) || /^webllm/i.test(n)).map(n => caches.delete(n))));
    }
    return p;
  }).catch(() => {});
}
function featureOf(u) {
  for (const k in FEAT) if (FEAT[k].p && FEAT[k].p.some(p => u.pathname.includes(p))) return k;
  for (const k in FEAT) if (FEAT[k].h.some(h => u.hostname === h || u.hostname.endsWith('.' + h))) return k;
  return '';
}
function isBlocked(u) {
  if (u.origin === location.origin) return false;
  if (u.hostname === 'braveheart30.github.io' && /\/FPLN-\/(control|version)\.json$/.test(u.pathname)) return false;   // the safety signal always gets through
  if (!SAFE) return !DATA_OK.some(h => u.hostname === h || u.hostname.endsWith('.' + h));
  if (SAFE.state === 'freeze' || SAFE.state === 'erase') return true;
  const f = featureOf(u);
  if (f && (SAFE.off || []).includes(f)) return true;
  return !DATA_OK.some(h => u.hostname === h || u.hostname.endsWith('.' + h));
}

self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('fpln-') && k !== CACHE && k !== CTL).map(k => caches.delete(k)))).then(() => refresh(true)).then(() => self.clients.claim())); });
/* The worker stamps a browser security policy onto every FPLN page it serves, so the browser enforces the allowlist
   even if a release ships without the app's guard script. While paused it uses the strict policy, blocks pop-ups,
   and if the page it would serve is missing the guard, it serves its own pause screen instead. */
const LINKS = "https://braveheart30.github.io https://generativelanguage.googleapis.com https://api.anthropic.com https://huggingface.co https://*.huggingface.co https://*.hf.co https://raw.githubusercontent.com https://cdn.jsdelivr.net https://esm.run https://docs.google.com https://api.open-meteo.com https://*.instructure.com https://fonts.googleapis.com https://fonts.gstatic.com";
const CSP_OPEN = "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' blob: https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://unpkg.com https://esm.run; " +
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' data: blob:; " +
  "connect-src 'self' data: blob: " + LINKS + "; worker-src 'self' blob:; frame-src 'self' about: data: blob:; form-action 'self' https://docs.google.com; object-src 'none'; base-uri 'self'";
const CSP_LOCKED = "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; " +
  "connect-src 'self' https://braveheart30.github.io; form-action 'none'; frame-src 'self' about: data:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; " +
  "sandbox allow-scripts allow-same-origin allow-modals";
const PAUSED_PAGE = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FPLN</title>' +
  '<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#070a0f;color:#e8f2f8;font:15px/1.5 system-ui,sans-serif;padding:24px 16px}main{max-width:440px;display:grid;gap:12px}h1{margin:0;font:700 24px/1.2 system-ui,sans-serif}p{margin:0;color:#a9bccb}</style></head>' +
  '<body><main><h1 id="h">FPLN is paused</h1><p id="p">The FPLN team paused FPLN as a safety step. Your data is still on this device, and nothing leaves it while FPLN is paused. Reminders and alarms are off until FPLN is back.</p></main>' +
  '<script>if(location.hash==="#erase"){document.getElementById("h").textContent="FPLN has been shut down";document.getElementById("p").textContent="The FPLN team shut FPLN down as a safety step.";}</script></body></html>';
function isLocked() { return !!(SAFE && (SAFE.state === 'freeze' || SAFE.state === 'erase')); }
async function harden(res) {
  if (!res || !res.ok) return res;
  const type = res.headers.get('content-type') || '';
  if (type && !type.includes('text/html')) return res;
  const h = new Headers(res.headers);
  const locked = isLocked();
  h.set('Content-Security-Policy', locked ? CSP_LOCKED : CSP_OPEN);
  let body = await res.text();
  if (locked && body.indexOf('id="fpln-safety"') < 0) body = SAFE.state === 'erase' ? PAUSED_PAGE.replace('<body>', '<body data-x>').replace('location.hash==="#erase"', 'true') : PAUSED_PAGE;   // the app's guard is missing: don't run it while paused
  h.set('Content-Type', 'text/html; charset=utf-8'); h.delete('Content-Length');
  return new Response(body, { status: res.status, statusText: res.statusText, headers: h });
}
function fresh(req) {
  // network first (4 s), so an update shows up the next time FPLN opens; the cache covers offline
  return new Promise(resolve => {
    let done = false;
    const t = setTimeout(() => { caches.match(req, {ignoreSearch: true}).then(r => { if (r && !done) { done = true; resolve(r); } }); }, 4000);
    fetch(req, {cache: 'no-cache'}).then(res => {
      if (res && res.ok && !(SAFE && SAFE.state === 'erase')) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req.mode === 'navigate' ? './' : req, copy)); }
      if (!done) { done = true; clearTimeout(t); resolve(res); }
    }).catch(() => caches.match(req.mode === 'navigate' ? './' : req, {ignoreSearch: true}).then(r => { if (!done) { done = true; clearTimeout(t); resolve(r || Response.error()); } }));
  });
}
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (url.origin !== location.origin) {
    // safety layer: outside traffic, any method
    if (SAFE === null) { e.respondWith(ready.then(() => isBlocked(url) ? Response.error() : fetch(req))); return; }
    if (isBlocked(url)) { e.respondWith(Response.error()); return; }
    return;
  }
  if (req.method !== 'GET') return;
  if (url.pathname.endsWith('version.json') || url.pathname.endsWith('control.json')) return;
  if (req.mode === 'navigate' || url.pathname.endsWith('/') || url.pathname.endsWith('index.html')) { e.waitUntil(ready.then(() => refresh(false))); e.respondWith(ready.then(() => fresh(req)).then(harden)); return; }
  e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => { if (res.ok && !(SAFE && SAFE.state === 'erase')) { const c = res.clone(); caches.open(CACHE).then(x => x.put(req, c)); } return res; })));
});
self.addEventListener('message', e => {
  const d = e.data;
  if (d && d.t === 'fpln-ring' && typeof d.h === 'string' && /^[0-9a-f]{0,24}$/.test(d.h) && d.h !== RING) {
    RING = d.h; e.waitUntil(caches.open(CTL).then(c => c.put('ring', new Response(RING))).then(() => refresh(true)));
  }
  if (d === 'fpln-safety-check') e.waitUntil(refresh(true));
});
