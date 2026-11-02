/* FPLN shutdown service worker (safety layer 7). Replaces FPLN's worker on the official site:
   deletes FPLN's offline copy, refuses all outside traffic, sends every open FPLN window to the shutdown page, then removes itself. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys()
    .then(ns => Promise.all(ns.filter(n => n.startsWith('fpln') || /^webllm/i.test(n)).map(n => caches.delete(n))))
    .then(() => self.clients.claim())
    .then(() => self.clients.matchAll({ type: 'window' }))
    .then(cs => Promise.all(cs.map(c => c.navigate(c.url).catch(() => {}))))
    .then(() => self.registration.unregister()));
});
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin) { e.respondWith(Response.error()); return; }
  e.respondWith(fetch(e.request, { cache: 'no-store' }));
});
