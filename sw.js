// TCRM v2.6 - Aggressive cache bust
const CACHE_VERSION = 'tcrm-v2.8-' + Date.now();

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.keys().then(names => 
    Promise.all(names.map(n => caches.delete(n)))
  ));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(names => 
      Promise.all(names.map(n => caches.delete(n)))
    ).then(() => clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    fetch(e.request, { cache: 'no-store' })
      .then(response => {
        const nr = new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers
        });
        nr.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
        nr.headers.set('Pragma', 'no-cache');
        return nr;
      })
      .catch(() => fetch(e.request))
  );
});
