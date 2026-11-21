// M-CHAT push serveri (Cloudflare Worker)
// Vazifasi: xabar yoki qo'ng'iroq bo'lganda, qabul qiluvchining telefoniga bildirishnoma yuborish.
const PROJECT_ID = 'mchat-5e7cc';
const ALLOWED_ORIGIN = 'https://zogorap-art.github.io';
const VAPID_PUBLIC = 'BC6XFcatino1ZOBW4Pwiq7zQVtXJGNOh81TCNXS_eWrOPuNQGXy-P3MZAWw60b3aCUCEsebY3ckjQwyXnzLCdmY';
const VAPID_JWK = {"kty": "EC", "crv": "P-256", "x": "LpcVxq2KejVk4Fbg_CKrvNBW1ckY06HzVMI1dL95as4", "y": "PuNQGXy-P3MZAWw60b3aCUCEsebY3ckjQwyXnzLCdmY", "d": "tHK-O7lYTX0Np45rhXmelYXJEgpKoGVKBDojdENPYfk"};
const VAPID_SUBJECT = 'mailto:mchat@users.noreply.github.com';
const PUSH_HOSTS = ['fcm.googleapis.com', 'updates.push.services.mozilla.com', 'push.services.mozilla.com', 'notify.windows.com', 'push.apple.com', 'web.push.apple.com'];

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64uEncode(buf){
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for(let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uDecode(str){
  str = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while(str.length % 4) str += '=';
  const bin = atob(str);
  const u = new Uint8Array(bin.length);
  for(let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function concat(...arrs){
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for(const a of arrs){ out.set(a, o); o += a.length; }
  return out;
}

/* ---------- Firebase ID token tekshiruvi ---------- */
let jwksCache = null, jwksAt = 0;
async function getJwks(){
  if(jwksCache && Date.now() - jwksAt < 3600 * 1000) return jwksCache;
  const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  const j = await r.json();
  jwksCache = j.keys; jwksAt = Date.now();
  return jwksCache;
}
async function verifyIdToken(token){
  const parts = String(token).split('.');
  if(parts.length !== 3) throw new Error('bad token');
  const header = JSON.parse(dec.decode(b64uDecode(parts[0])));
  const payload = JSON.parse(dec.decode(b64uDecode(parts[1])));
  if(header.alg !== 'RS256') throw new Error('alg');
  const keys = await getJwks();
  const jwk = keys.find(k => k.kid === header.kid);
  if(!jwk) throw new Error('kid');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64uDecode(parts[2]), enc.encode(parts[0] + '.' + parts[1]));
  if(!ok) throw new Error('signature');
  const now = Math.floor(Date.now() / 1000);
  if(payload.aud !== PROJECT_ID) throw new Error('aud');
  if(payload.iss !== 'https://securetoken.google.com/' + PROJECT_ID) throw new Error('iss');
  if(!payload.sub || typeof payload.sub !== 'string') throw new Error('sub');
  if(payload.exp < now) throw new Error('expired');
  if(payload.iat > now + 300) throw new Error('iat');
  return payload;
}

/* ---------- Firestore (foydalanuvchining o'z tokeni bilan o'qiladi) ---------- */
async function fsGet(path, idToken){
  const r = await fetch('https://firestore.googleapis.com/v1/projects/' + PROJECT_ID + '/databases/(default)/documents/' + path, {
    headers: { 'Authorization': 'Bearer ' + idToken }
  });
  if(!r.ok) return null;
  const j = await r.json();
  const out = {};
  for(const k in (j.fields || {})){
    const v = j.fields[k];
    if('stringValue' in v) out[k] = v.stringValue;
  }
  return out;
}

/* ---------- Web Push shifrlash (RFC 8291, aes128gcm) ---------- */
async function hkdf(salt, ikm, info, length){
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: info }, key, length * 8);
  return new Uint8Array(bits);
}
async function encryptPayload(p256dhB64, authB64, plaintext, opts){
  opts = opts || {};
  const uaPublic = b64uDecode(p256dhB64);
  const authSecret = b64uDecode(authB64);
  let asKeys = opts.asKeys;
  if(!asKeys) asKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asKeys.privateKey, 256));
  const keyInfo = concat(enc.encode('WebPush: info\0'), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, ecdh, keyInfo, 32);
  const salt = opts.salt || crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const data = concat(plaintext, new Uint8Array([2]));
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, data));
  const rs = new Uint8Array([0, 0, 0x10, 0]);               // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

/* ---------- VAPID ---------- */
async function vapidHeader(endpoint){
  const aud = new URL(endpoint).origin;
  const header = b64uEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64uEncode(enc.encode(JSON.stringify({ aud: aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT })));
  const key = await crypto.subtle.importKey('jwk', VAPID_JWK, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(header + '.' + claims)));
  return 'vapid t=' + header + '.' + claims + '.' + b64uEncode(sig) + ', k=' + VAPID_PUBLIC;
}

async function sendPush(sub, payloadObj, ttl){
  const body = await encryptPayload(sub.p256dh, sub.auth, enc.encode(JSON.stringify(payloadObj)));
  const r = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': await vapidHeader(sub.endpoint),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': String(ttl),
      'Urgency': 'high'
    },
    body: body
  });
  return r.status;
}

/* ---------- HTTP ---------- */
function cors(origin){
  const h = { 'Vary': 'Origin' };
  if(origin === ALLOWED_ORIGIN){
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Headers'] = 'Authorization, Content-Type';
    h['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}
function json(obj, status, origin){
  return new Response(JSON.stringify(obj), { status: status, headers: Object.assign({ 'Content-Type': 'application/json' }, cors(origin)) });
}

const MEDIA_MIMES = ['image/jpeg', 'image/png', 'image/webp', 'video/mp4', 'video/webm', 'video/quicktime', 'video/3gpp'];
const MAX_MEDIA = 20 * 1024 * 1024;     // 20 MB
const MEDIA_TTL = 24 * 60 * 60;         // 24 soat

function randomId(){
  const b = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}
async function authUser(request){
  const auth = request.headers.get('Authorization') || '';
  const idToken = auth.replace(/^Bearer\s+/i, '');
  const me = await verifyIdToken(idToken);
  return { me: me, idToken: idToken };
}

export default {
  async fetch(request, env){
    const origin = request.headers.get('Origin') || '';
    if(request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin) });
    const url = new URL(request.url);

    if(request.method === 'GET' && url.pathname === '/') return json({ ok: true, name: 'mchat-push', media: !!(env && env.MEDIA) }, 200, origin);

    /* ---------- Rasm/video yuklash ---------- */
    if(request.method === 'POST' && url.pathname === '/media'){
      let who;
      try{ who = await authUser(request); }catch(e){ return json({ error: 'auth' }, 401, origin); }
      if(!env || !env.MEDIA) return json({ error: 'KV (MEDIA) ulanmagan' }, 500, origin);
      const to = String(url.searchParams.get('to') || '');
      if(!/^[A-Za-z0-9]{10,40}$/.test(to)) return json({ error: 'bad recipient' }, 400, origin);
      const mime = String(request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
      if(!MEDIA_MIMES.includes(mime)) return json({ error: 'format' }, 415, origin);
      const len = Number(request.headers.get('Content-Length') || 0);
      if(len > MAX_MEDIA) return json({ error: 'katta' }, 413, origin);
      const buf = await request.arrayBuffer();
      if(buf.byteLength === 0 || buf.byteLength > MAX_MEDIA) return json({ error: 'hajm' }, 413, origin);
      let id = String(url.searchParams.get('id') || '');
      if(!/^[a-f0-9]{24}$/.test(id)) id = randomId();
      else{
        const ex = await env.MEDIA.getWithMetadata(id, 'arrayBuffer');
        if(ex && ex.value) return json({ error: 'id band' }, 409, origin);
      }
      await env.MEDIA.put(id, buf, { expirationTtl: MEDIA_TTL, metadata: { from: who.me.sub, to: to, mime: mime } });
      return json({ id: id }, 200, origin);
    }

    /* ---------- Rasm/video olish ---------- */
    const mm = /^\/media\/([a-f0-9]{24})$/.exec(url.pathname);
    if(request.method === 'GET' && mm){
      let who;
      try{ who = await authUser(request); }catch(e){ return json({ error: 'auth' }, 401, origin); }
      if(!env || !env.MEDIA) return json({ error: 'KV (MEDIA) ulanmagan' }, 500, origin);
      const r = await env.MEDIA.getWithMetadata(mm[1], 'arrayBuffer');
      if(!r || !r.value) return json({ error: 'topilmadi' }, 404, origin);
      const md = r.metadata || {};
      if(md.from !== who.me.sub && md.to !== who.me.sub) return json({ error: 'ruxsat yo\'q' }, 403, origin);
      return new Response(r.value, { status: 200, headers: Object.assign({
        'Content-Type': md.mime || 'application/octet-stream',
        'Cache-Control': 'private, max-age=86400'
      }, cors(origin)) });
    }

    /* ---------- Push bildirishnoma ---------- */
    if(request.method !== 'POST' || url.pathname !== '/notify') return json({ error: 'not found' }, 404, origin);
    try{
      const auth = request.headers.get('Authorization') || '';
      const idToken = auth.replace(/^Bearer\s+/i, '');
      const me = await verifyIdToken(idToken);
      const req = await request.json();
      const to = String(req.to || '');
      if(!/^[A-Za-z0-9]{10,40}$/.test(to) || to === me.sub) return json({ error: 'bad recipient' }, 400, origin);
      const kind = ['msg', 'call', 'callend'].includes(req.kind) ? req.kind : 'msg';

      const sub = await fsGet('push/' + to, idToken);
      if(!sub || !sub.endpoint || !sub.p256dh || !sub.auth) return json({ ok: false, reason: 'no-subscription' }, 200, origin);
      let host = '';
      try{ const u = new URL(sub.endpoint); host = u.hostname; if(u.protocol !== 'https:') throw 0; }catch(e){ return json({ error: 'bad endpoint' }, 400, origin); }
      if(!PUSH_HOSTS.some(h => host === h || host.endsWith('.' + h))) return json({ error: 'endpoint host' }, 400, origin);

      const meDoc = await fsGet('users/' + me.sub, idToken);
      const name = String((meDoc && meDoc.name) || 'M-CHAT').slice(0, 60);
      let body = '', ttl = 3600;
      if(kind === 'msg') body = String(req.text || 'Yangi xabar').slice(0, 120);
      else if(kind === 'call'){ body = req.text === 'video' ? "📹 Kiruvchi video qo'ng'iroq" : "📞 Kiruvchi ovozli qo'ng'iroq"; ttl = 40; }
      else { body = ''; ttl = 120; }
      const status = await sendPush(sub, { kind: kind, title: name, body: body, from: me.sub }, ttl);
      return json({ ok: status >= 200 && status < 300, status: status }, 200, origin);
    }catch(e){
      return json({ error: String(e && e.message || e).slice(0, 80) }, 401, origin);
    }
  }
};
