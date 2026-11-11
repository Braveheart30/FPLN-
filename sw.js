/* FPLN at its old address (hand-off). Replaces the old FPLN worker on installed copies, drops the old offline copy,
   and reloads open FPLN windows so they show the move page. Serves nothing itself. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  for (const k of await caches.keys()) await caches.delete(k);
  await self.clients.claim();
  for (const c of await self.clients.matchAll({type: 'window'})) { try { await c.navigate(c.url); } catch (err) {} }
})()));
