/**
 * ============================================================================
 * WOO PASS — Service Worker (sw.js)
 * High-Security PWA Offline Cache & App Shell Provider
 * ============================================================================
 */

const CACHE_NAME = 'woopass-v3.0.0';

// Critical core assets for offline standalone launch
const PRECACHE_ASSETS = [
  './',
  './index.html',
  './app.html',
  './manifest.json',
  './css/bootstrap.min.css',
  './css/bootstrap-icons.min.css',
  './css/fonts/bootstrap-icons.woff2',
  './css/fonts/bootstrap-icons.woff',
  './css/app.css',
  './css/responsive.css',
  './js/bootstrap.bundle.min.js',
  './js/security-guard.js',
  './logo.png',
  './assets/logo.png',
  './assets/icon.png',
  './assets/icon-192.png',
  './assets/icon-512.png',
  './assets/icon-apple-touch.png',
  './assets/badge-72.png'
];

// Install Event — precache the app shell
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Use cache.addAll with individual catch so 1 failure doesn't break all
      return Promise.allSettled(
        PRECACHE_ASSETS.map((url) =>
          cache.add(url).catch((err) => {
            console.warn(`[ServiceWorker] Cache fail for ${url}:`, err);
          })
        )
      );
    }).then(() => self.skipWaiting())
  );
});

// Activate Event — purge outdated cache versions
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => {
            console.log(`[ServiceWorker] Purging legacy cache: ${name}`);
            return caches.delete(name);
          })
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch Event — Network-first for dynamic & API calls, Stale-while-revalidate for static shell
self.addEventListener('fetch', (event) => {
  const request = event.request;

  // Only handle GET requests
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // Bypass cache for Firestore, Firebase Auth, Google APIs, and external iframes
  if (
    url.hostname.includes('googleapis.com') ||
    url.hostname.includes('firebaseio.com') ||
    url.hostname.includes('identitytoolkit') ||
    url.hostname.includes('netlify.app') ||
    url.hostname.includes('gstatic.com')
  ) {
    return; // allow default network request
  }

  // Same-origin or local static files: Stale-While-Revalidate
  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      const fetchPromise = fetch(request)
        .then((networkResponse) => {
          // Cache successful 200 responses
          if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, responseToCache);
            });
          }
          return networkResponse;
        })
        .catch(() => {
          // If offline and requesting an HTML page, serve cached index.html or app.html
          if (request.headers.get('accept')?.includes('text/html')) {
            return caches.match('./index.html') || cachedResponse;
          }
        });

      return cachedResponse || fetchPromise;
    })
  );
});
