// Ancien service worker de l'app (avant son déplacement sur /app) : il se retire tout seul
// pour laisser le site vitrine s'afficher normalement à la racine.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => {
  e.waitUntil((async () => {
    for (const k of await caches.keys()) if (!k.startsWith('lma-app-')) await caches.delete(k);
    await self.registration.unregister();
    for (const c of await self.clients.matchAll({ type: 'window' })) c.navigate(c.url);
  })());
});
