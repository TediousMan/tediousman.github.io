const CORS_ORIGIN = 'https://tediousman.github.io';
const GITHUB_API  = 'https://api.github.com';
const JWT_ALG     = { name: 'HMAC', hash: 'SHA-256' };
const JWT_TTL_SEC = 30 * 24 * 60 * 60; // 30 天

// ─── CORS helpers ─────────────────────────────────────────────────────────────
function corsHeaders(origin) {
  const allowed = (origin === CORS_ORIGIN || origin === 'http://127.0.0.1:4000')
    ? origin : CORS_ORIGIN;
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET, PUT, DELETE, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function withCors(response, origin) {
  const h = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(origin))) h.set(k, v);
  return new Response(response.body, { status: response.status, headers: h });
}

// ─── JWT helpers ──────────────────────────────────────────────────────────────
async function importKey(secret) {
  const enc = new TextEncoder().encode(secret);
  return crypto.subtle.importKey('raw', enc, JWT_ALG, false, ['sign', 'verify']);
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function signJWT(payload, secret) {
  const key  = await importKey(secret);
  const enc  = new TextEncoder();
  const head = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig  = await crypto.subtle.sign('HMAC', key, enc.encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(sig)}`;
}

async function verifyJWT(token, secret) {
  try {
    const [head, body, sig] = token.split('.');
    if (!head || !body || !sig) return null;
    const key = await importKey(secret);
    const enc = new TextEncoder();
    const ok  = await crypto.subtle.verify('HMAC', key,
      Uint8Array.from(atob(sig.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
      enc.encode(`${head}.${body}`)
    );
    if (!ok) return null;
    const payload = JSON.parse(atob(body.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ─── Rate limiting helpers ────────────────────────────────────────────────────
const RATE_LIMIT_MAX    = 5;   // 最多 5 次失敗
const RATE_LIMIT_WIN_S  = 900; // 15 分鐘視窗

async function getRateKey(ip) {
  return `https://rate-limit-fake-host/login/${ip}`;
}

async function getRateLimitEntry(ip) {
  const cache = caches.default;
  const key   = await getRateKey(ip);
  const res   = await cache.match(key);
  if (!res) return { count: 0, resetAt: 0 };
  return res.json();
}

async function incrementRateLimit(ip, ctx) {
  const cache    = caches.default;
  const key      = await getRateKey(ip);
  const entry    = await getRateLimitEntry(ip);
  const now      = Math.floor(Date.now() / 1000);
  const resetAt  = entry.resetAt || now + RATE_LIMIT_WIN_S;
  const count    = (now < resetAt ? entry.count : 0) + 1;
  const ttl      = Math.max(resetAt - now, 1);

  ctx.waitUntil(cache.put(key, new Response(JSON.stringify({ count, resetAt }),
    { headers: { 'Cache-Control': `max-age=${ttl}`, 'Content-Type': 'application/json' } })));
  return { count, resetAt };
}

async function resetRateLimit(ip, ctx) {
  const cache = caches.default;
  ctx.waitUntil(cache.delete(await getRateKey(ip)));
}

// ─── Route handlers ───────────────────────────────────────────────────────────
async function handleLogin(request, env, ctx) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  // 先檢查是否超過上限
  const { count, resetAt } = await getRateLimitEntry(ip);
  const now = Math.floor(Date.now() / 1000);
  if (count >= RATE_LIMIT_MAX && now < resetAt) {
    const retryAfter = resetAt - now;
    return new Response(JSON.stringify({ error: '登入嘗試過於頻繁，請稍後再試' }),
      { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': String(retryAfter) } });
  }

  let body;
  try { body = await request.json(); }
  catch { return new Response('Bad Request', { status: 400 }); }

  const { username, password } = body;
  if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
    const { count: newCount } = await incrementRateLimit(ip, ctx);
    // 指數退避延遲：1次=1s, 2次=5s, 3次+=30s
    const delay = newCount >= 3 ? 30000 : newCount === 2 ? 5000 : 1000;
    await new Promise(r => setTimeout(r, delay));
    return new Response(JSON.stringify({ error: '帳號或密碼錯誤' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // 登入成功，清除失敗紀錄
  await resetRateLimit(ip, ctx);
  const nowSec = Math.floor(Date.now() / 1000);
  const token  = await signJWT({ sub: username, iat: nowSec, exp: nowSec + JWT_TTL_SEC }, env.JWT_SECRET);
  return new Response(JSON.stringify({ token }),
    { status: 200, headers: { 'Content-Type': 'application/json' } });
}

async function handleGitHubProxy(request, url, env) {
  // 驗證 JWT
  const auth = request.headers.get('Authorization') || '';
  const jwt  = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!jwt) return new Response('Unauthorized', { status: 401 });

  const payload = await verifyJWT(jwt, env.JWT_SECRET);
  if (!payload) return new Response('Unauthorized', { status: 401 });

  // 轉發到 GitHub API（僅允許存取指定 repo）
  const ghPath     = url.pathname.replace(/^\/api\/github/, '');
  if (!/^\/repos\/TediousMan\/tediousman\.github\.io\//.test(ghPath)) {
    return new Response('Forbidden', { status: 403 });
  }
  const ghUrl      = `${GITHUB_API}${ghPath}${url.search}`;
  const newHeaders = new Headers(request.headers);
  newHeaders.set('Authorization', `token ${env.GITHUB_TOKEN}`);
  newHeaders.delete('Origin');
  newHeaders.delete('Referer');

  const ghReq = new Request(ghUrl, { method: request.method, headers: newHeaders, body: request.body });
  return fetch(ghReq);
}

// ─── Main handler ─────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const url    = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    let response;
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      response = await handleLogin(request, env, ctx);
    } else if (url.pathname.startsWith('/api/github/')) {
      response = await handleGitHubProxy(request, url, env);
    } else if (url.pathname === '/api/spotify/oembed' && request.method === 'GET') {
      const spotifyUrl = url.searchParams.get('url');
      if (!spotifyUrl) {
        response = new Response('Missing url parameter', { status: 400 });
      } else {
        response = await fetch('https://open.spotify.com/oembed?url=' + encodeURIComponent(spotifyUrl));
      }
    } else {
      response = new Response('Not Found', { status: 404 });
    }

    return withCors(response, origin);
  }
};
