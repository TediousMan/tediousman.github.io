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

// ─── Route handlers ───────────────────────────────────────────────────────────
async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return new Response('Bad Request', { status: 400 }); }

  const { username, password } = body;
  if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
    await new Promise(r => setTimeout(r, 500)); // 防暴力破解延遲
    return new Response(JSON.stringify({ error: '帳號或密碼錯誤' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  const now   = Math.floor(Date.now() / 1000);
  const token = await signJWT({ sub: username, iat: now, exp: now + JWT_TTL_SEC }, env.JWT_SECRET);
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

  // 轉發到 GitHub API
  const ghPath     = url.pathname.replace(/^\/api\/github/, '');
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
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url    = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    let response;
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      response = await handleLogin(request, env);
    } else if (url.pathname.startsWith('/api/github/')) {
      response = await handleGitHubProxy(request, url, env);
    } else {
      response = new Response('Not Found', { status: 404 });
    }

    return withCors(response, origin);
  }
};
