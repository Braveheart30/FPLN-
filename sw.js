/* FPLN service worker: newest version on every launch, works offline after the first visit. */
const CACHE = 'fpln-202610312116';
const CORE = ['./', './index.html', './manifest.webmanifest', './favicon.ico', './icons/icon-32.png', './icons/icon-64.png', './icons/icon-192.png', './icons/icon-512.png'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('fpln-') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
function fresh(req) {
  // network first (4 s), so an update shows up the next time FPLN opens; the cache covers offline
  return new Promise(resolve => {
    let done = false;
    const t = setTimeout(() => { caches.match(req, {ignoreSearch: true}).then(r => { if (r && !done) { done = true; resolve(r); } }); }, 4000);
    fetch(req, {cache: 'no-cache'}).then(res => {
      if (res && res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req.mode === 'navigate' ? './' : req, copy)); }
      if (!done) { done = true; clearTimeout(t); resolve(res); }
    }).catch(() => caches.match(req.mode === 'navigate' ? './' : req, {ignoreSearch: true}).then(r => { if (!done) { done = true; clearTimeout(t); resolve(r || Response.error()); } }));
  });
}
self.addEventListener('fetch', e => {
  const req = e.request, url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.endsWith('version.json')) return;
  if (req.mode === 'navigate' || url.pathname.endsWith('/') || url.pathname.endsWith('index.html')) { e.respondWith(fresh(req)); return; }
  e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => { if (res.ok) { const c = res.clone(); caches.open(CACHE).then(x => x.put(req, c)); } return res; })));
});
