/* Service Worker «Конуры».
   Задача — сделать приложение устанавливаемым и работоспособным при плохой сети.
   Живые данные (api.php) НИКОГДА не кэшируются: медкарта и назначения всегда свежие.
   Оболочка (index.html, иконки) кэшируется, чтобы приложение открывалось офлайн. */

const CACHE = 'konura-v3';
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icon-192.png',
  './icon-512.png',
  './apple-touch-icon.png',
];

self.addEventListener('install', (e) => {
  // addAll упадёт целиком, если хоть один файл недоступен, — кэшируем поштучно.
  e.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await Promise.all(SHELL.map((u) => cache.add(u).catch(() => null)));
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;                     // POST/PUT/DELETE — только сеть

  const url = new URL(req.url);
  if (url.pathname.includes('api.php')) return;         // данные API — не трогаем вообще

  // Открытие приложения: сначала сеть (свежая версия), офлайн — из кэша.
  if (req.mode === 'navigate') {
    e.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        const cache = await caches.open(CACHE);
        cache.put('./index.html', fresh.clone());
        return fresh;
      } catch (_) {
        return (await caches.match('./index.html')) || Response.error();
      }
    })());
    return;
  }

  // Иконки, шрифты и прочая статика: из кэша, иначе сеть и дозаписываем.
  e.respondWith((async () => {
    const cached = await caches.match(req);
    if (cached) return cached;
    try {
      const fresh = await fetch(req);
      if (fresh && fresh.ok && fresh.type === 'basic') {
        const cache = await caches.open(CACHE);
        cache.put(req, fresh.clone());
      }
      return fresh;
    } catch (_) {
      return Response.error();
    }
  })());
});
