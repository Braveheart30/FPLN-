/* FPLN service worker: newest version on every launch, works offline after the first visit.
   Safety layer 6: reads control.json on its own and, while FPLN is paused or shut down, refuses
   every request to another site at the network layer, even if the page's own code fails. */
const CACHE = 'fpln-202611012300';
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
let SAFE = null, lastCheck = 0;           // {state, id, off:[]}
const ready = caches.open(CTL).then(c => c.match('state')).then(r => r ? r.json() : null).then(s => { SAFE = s || { state: 'none', off: [] }; }).catch(() => { SAFE = { state: 'none', off: [] }; });

function save(s) { SAFE = s; return caches.open(CTL).then(c => c.put('state', new Response(JSON.stringify(s), { headers: { 'content-type': 'application/json' } }))); }
function refresh(force) {
  if (!force && Date.now() - lastCheck < 60000) return Promise.resolve();
  lastCheck = Date.now();
  return fetch('./control.json?sw=' + Date.now(), { cache: 'no-store' }).then(r => r.ok ? r.json() : null).then(j => {
    if (!j) return;
    const k = j.kill && ['freeze', 'erase'].includes(j.kill.state) ? j.kill : { state: 'none' };
    const off = Array.isArray(j.off) ? j.off.filter(x => FEAT[x]) : [];
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
  if (!SAFE) return false;
  if (SAFE.state === 'freeze' || SAFE.state === 'erase') return true;
  const f = featureOf(u);
  return !!(f && (SAFE.off || []).includes(f));
}

self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('fpln-') && k !== CACHE && k !== CTL).map(k => caches.delete(k)))).then(() => refresh(true)).then(() => self.clients.claim())); });
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
  if (req.mode === 'navigate' || url.pathname.endsWith('/') || url.pathname.endsWith('index.html')) { e.waitUntil(ready.then(() => refresh(false))); e.respondWith(fresh(req)); return; }
  e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => { if (res.ok && !(SAFE && SAFE.state === 'erase')) { const c = res.clone(); caches.open(CACHE).then(x => x.put(req, c)); } return res; })));
});
self.addEventListener('message', e => { if (e.data === 'fpln-safety-check') e.waitUntil(refresh(true)); });
