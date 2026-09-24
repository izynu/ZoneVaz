// Service Worker for ZoneVaz PWA
const CACHE_NAME = 'zonevaz-v4';
const APP_SHELL = [
  './',
  './index.html',
  './login.html',
  './download.html',
  './profile.html',
  './playlists.html',
  './trending.html',
  './visualizer.html',
  './lyrics.html',
  './lounge.html',
  './admin.html',
  './common.js',
  './manifest.json'
];

// Install: precache the app shell
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
      .catch(err => console.log('[ZoneVaz SW] Precache skipped (some files offline):', err))
  );
});

// Activate: clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Fetch: network-first for navigation (fresh content), cache-first for assets
self.addEventListener('fetch', event => {
  const request = event.request;

  // Only handle GET, same-origin requests
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Never cache API calls (they need live data)
  if (url.pathname.startsWith('/api/')) return;

  // HTML navigation: network first, fall back to cache, then to index.html
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(response => {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
          return response;
        })
        .catch(() =>
          caches.match(request).then(cached => cached || caches.match('./index.html'))
        )
    );
    return;
  }

  // Assets: stale-while-revalidate
  event.respondWith(
    caches.match(request).then(cached => {
      const fetchPromise = fetch(request)
        .then(response => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => cached);
      return cached || fetchPromise;
    })
  );
});