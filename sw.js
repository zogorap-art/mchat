const CACHE_NAME = "mchat-cache-v6";
const ASSETS = ["./", "./index.html", "./manifest.json", "./icon-192.png", "./icon-512.png", "./icon-180.png", "./icon-32.png", "./icon-16.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

// Network first: yangi versiya doim olinadi, internet bo'lmasa keshdan ochiladi
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});


// ===== Push bildirishnomalar (telefon bloklangan yoki ilova yopiq bo'lganda) =====
self.addEventListener("push", (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; } catch (e) {}
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const visible = wins.some((w) => w.visibilityState === "visible");

    if (d.kind === "callend") {
      const old = await self.registration.getNotifications({ tag: "mchat-call" });
      old.forEach((n) => n.close());
      if (visible) return;
      return self.registration.showNotification(d.title || "M-CHAT", {
        body: "O'tkazib yuborilgan qo'ng'iroq",
        icon: "icon-192.png", badge: "icon-192.png", tag: "mchat-missed"
      });
    }

    // Ilova ochiq bo'lsa, o'zi ko'rsatadi
    if (visible) return;

    const isCall = d.kind === "call";
    return self.registration.showNotification(d.title || "M-CHAT", {
      body: d.body || "",
      icon: "icon-192.png",
      badge: "icon-192.png",
      tag: isCall ? "mchat-call" : "mchat-msg-" + (d.from || ""),
      renotify: true,
      requireInteraction: isCall,
      silent: false,
      actions: isCall ? [{ action: "accept", title: "📞 Qabul qilish" }, { action: "decline", title: "Rad etish" }] : [],
      vibrate: isCall ? [500, 250, 500, 250, 500, 250, 500] : [200, 100, 200],
      data: { kind: d.kind, from: d.from }
    });
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  if (event.action === "decline") return;
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of wins) {
      if ("focus" in w) { await w.focus(); return; }
    }
    return self.clients.openWindow("./");
  })());
});
