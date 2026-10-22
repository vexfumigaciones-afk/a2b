const CACHE='a2b-vex-v1.3-secure';
const ASSETS=['/','/app','/manifest.webmanifest','/icon-192.png','/icon-512.png','/a2b-ops.js'];
self.addEventListener('install',e=>{
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).catch(()=>{}));
});
self.addEventListener('activate',e=>e.waitUntil(
  caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())
));
self.addEventListener('fetch',e=>{
  const req=e.request,url=new URL(req.url);
  if(req.method!=='GET'||url.origin!==self.location.origin||url.pathname.startsWith('/api/')||url.pathname==='/setup'||req.headers.has('authorization'))return;
  if(!ASSETS.includes(url.pathname))return;
  e.respondWith(fetch(req).then(r=>{
    if(r.ok && !/no-store|private/i.test(r.headers.get('cache-control')||'')){
      const copy=r.clone();caches.open(CACHE).then(c=>c.put(req,copy)).catch(()=>{});
    }
    return r;
  }).catch(()=>caches.match(req)));
});
