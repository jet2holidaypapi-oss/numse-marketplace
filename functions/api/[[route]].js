/**
 * NUMSE Marketplace — Cloudflare Pages Function
 * Handles all /api/* routes via KV storage.
 * Binding required: NUMSE_KV (KV Namespace)
 */

const ADMIN_USER = 'Papi';
const PAYPAL_EMAIL = 'Jet2holidaypapi@gmail.com';

// ── In-memory rate limiting (per Worker isolate — basic protection)
// Cloudflare's WAF handles volumetric DDoS at the network level.
const rateLimits = {};
const adCooldowns = {};

// ── Crypto helpers (Web Crypto API — no Node.js crypto) ──────────────
function uid() {
  const arr = new Uint8Array(8);
  crypto.getRandomValues(arr);
  return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPw(str) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(str), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode('numse_salt_v1'), iterations: 100000, hash: 'SHA-512' },
    key, 512
  );
  return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, 500).replace(/[<>]/g, '');
}

// ── Rate limiting ─────────────────────────────────────────────────────
function rateLimit(ip, max = 20, windowMs = 60000) {
  const now = Date.now();
  if (!rateLimits[ip] || rateLimits[ip].resetAt < now) {
    rateLimits[ip] = { count: 1, resetAt: now + windowMs };
    return false;
  }
  rateLimits[ip].count++;
  return rateLimits[ip].count > max;
}
function authRateLimit(ip) { return rateLimit(ip, 10, 60000); }

function canWatchAd(username) {
  const now = Date.now();
  if (!adCooldowns[username] || adCooldowns[username] < now) {
    adCooldowns[username] = now + 5 * 60 * 1000;
    return true;
  }
  return false;
}

// ── Response helper ───────────────────────────────────────────────────
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  });
}

function getIP(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim()
    || 'unknown';
}

function authToken(request) {
  return (request.headers.get('Authorization') || '').replace('Bearer ', '').trim();
}

// ── KV helpers ────────────────────────────────────────────────────────
async function getUser(token, env) {
  if (!token) return null;
  const session = await env.NUMSE_KV.get('session:' + token, 'json');
  if (!session || session.expiresAt < Date.now()) {
    if (session) await env.NUMSE_KV.delete('session:' + token);
    return null;
  }
  return await env.NUMSE_KV.get('user:' + session.username, 'json');
}

async function createSession(username, env) {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  const token = [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
  const session = { username, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 };
  await env.NUMSE_KV.put('session:' + token, JSON.stringify(session), {
    expirationTtl: 7 * 24 * 60 * 60, // seconds
  });
  return token;
}

async function saveUser(user, env) {
  await env.NUMSE_KV.put('user:' + user.username, JSON.stringify(user));
}

async function getListings(env) {
  return (await env.NUMSE_KV.get('listings', 'json')) || [];
}

async function saveListings(listings, env) {
  await env.NUMSE_KV.put('listings', JSON.stringify(listings));
}

function convId(a, b, lid) {
  return [a, b].sort().join('__') + '__' + lid;
}

async function getUserConvs(username, env) {
  return (await env.NUMSE_KV.get('user_convs:' + username, 'json')) || [];
}

async function addUserConv(username, cid, env) {
  const convs = await getUserConvs(username, env);
  if (!convs.includes(cid)) {
    convs.push(cid);
    await env.NUMSE_KV.put('user_convs:' + username, JSON.stringify(convs));
  }
}

// ── Main handler ──────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method;
  const ip = getIP(request);

  // routeParts: ['register'] | ['buy','abc123'] | ['messages','cid'] etc.
  const routeParts = context.params.route || [];
  const fullPath = '/api/' + routeParts.join('/');

  if (method === 'OPTIONS') return json({});

  // Global rate limit
  if (rateLimit(ip, 120, 60000)) return json({ error: 'Too many requests' }, 429);

  async function readBody() {
    try { return await request.json(); } catch { return {}; }
  }

  // ── Register ──────────────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/register') {
    if (authRateLimit(ip)) return json({ error: 'Too many attempts. Wait a minute.' }, 429);
    const { username, password } = await readBody();
    const u = sanitize(username), pw = String(password || '');
    if (!u || !pw) return json({ error: 'Username and password required' }, 400);
    if (u.length < 3 || u.length > 30) return json({ error: 'Username must be 3–30 characters' }, 400);
    if (!/^[a-zA-Z0-9_]+$/.test(u)) return json({ error: 'Username: letters, numbers, underscores only' }, 400);
    if (pw.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);
    const existing = await env.NUMSE_KV.get('user:' + u);
    if (existing) return json({ error: 'Username taken' }, 409);
    const user = { username: u, password: await hashPw(pw), coins: 200, joinedAt: Date.now() };
    await saveUser(user, env);
    const token = await createSession(u, env);
    return json({ token, username: u, coins: 200 }, 201);
  }

  // ── Login ─────────────────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/login') {
    if (authRateLimit(ip)) return json({ error: 'Too many attempts. Wait a minute.' }, 429);
    const { username, password } = await readBody();
    const u = sanitize(username), pw = String(password || '');
    const user = await env.NUMSE_KV.get('user:' + u, 'json');
    // Constant-time: always hash even if user not found
    const expectedHash = user ? user.password : await hashPw('dummy_prevent_timing');
    const actualHash = await hashPw(pw);
    const match = timingSafeEqual(expectedHash, actualHash);
    if (!user || !match) return json({ error: 'Invalid username or password' }, 401);
    const token = await createSession(u, env);
    return json({ token, username: u, coins: user.coins });
  }

  // ── Me ────────────────────────────────────────────────────────────
  if (method === 'GET' && fullPath === '/api/me') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    return json({ username: user.username, coins: user.coins });
  }

  // ── Reset password ────────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/reset-password') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'You must be logged in to reset your password' }, 401);
    const { newPassword } = await readBody();
    const pw = String(newPassword || '');
    if (pw.length < 6) return json({ error: 'New password must be at least 6 characters' }, 400);
    user.password = await hashPw(pw);
    await saveUser(user, env);
    return json({ ok: true });
  }

  // ── Listings ──────────────────────────────────────────────────────
  if (method === 'GET' && fullPath === '/api/listings') {
    const q = sanitize(url.searchParams.get('q') || '');
    const cat = sanitize(url.searchParams.get('category') || '');
    let listings = await getListings(env);
    if (q) listings = listings.filter(l =>
      l.title.toLowerCase().includes(q.toLowerCase()) ||
      (l.desc || '').toLowerCase().includes(q.toLowerCase())
    );
    if (cat && cat !== 'All') listings = listings.filter(l => l.category === cat);
    listings.sort((a, b) => b.createdAt - a.createdAt);
    return json(listings);
  }

  if (method === 'POST' && fullPath === '/api/listings') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const body = await readBody();
    const title = sanitize(body.title), desc = sanitize(body.desc || '');
    const price = Number(body.price), category = sanitize(body.category || 'Other');
    const image = typeof body.image === 'string' && body.image.startsWith('data:image/') ? body.image : null;
    if (!title) return json({ error: 'Title is required' }, 400);
    if (title.length > 100) return json({ error: 'Title too long' }, 400);
    if (!price || isNaN(price) || price <= 0 || price > 1000000) return json({ error: 'Invalid price' }, 400);
    const listing = { id: uid(), seller: user.username, title, desc, price, category, image, createdAt: Date.now() };
    const listings = await getListings(env);
    listings.push(listing);
    await saveListings(listings, env);
    return json(listing, 201);
  }

  if (method === 'DELETE' && routeParts[0] === 'listings' && routeParts[1]) {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const id = sanitize(routeParts[1]);
    const listings = await getListings(env);
    const idx = listings.findIndex(l => l.id === id);
    if (idx === -1) return json({ error: 'Listing not found' }, 404);
    if (listings[idx].seller !== user.username && user.username !== ADMIN_USER)
      return json({ error: 'Not your listing' }, 403);
    listings.splice(idx, 1);
    await saveListings(listings, env);
    return json({ ok: true });
  }

  // ── Buy ───────────────────────────────────────────────────────────
  if (method === 'POST' && routeParts[0] === 'buy' && routeParts[1]) {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const id = sanitize(routeParts[1]);
    const listings = await getListings(env);
    const listing = listings.find(l => l.id === id);
    if (!listing) return json({ error: 'Listing not found' }, 404);
    if (listing.seller === user.username) return json({ error: "You can't buy your own listing" }, 400);
    if (user.coins < listing.price) return json({ error: 'Not enough coins' }, 400);
    const seller = await env.NUMSE_KV.get('user:' + listing.seller, 'json');
    user.coins -= listing.price;
    if (seller) { seller.coins += listing.price; await saveUser(seller, env); }
    await saveUser(user, env);
    await saveListings(listings.filter(l => l.id !== id), env);
    return json({ ok: true, coins: user.coins });
  }

  // ── Watch ad ──────────────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/watch-ad') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    if (!canWatchAd(user.username)) return json({ error: 'Ad cooldown active. Try again in 5 minutes.' }, 429);
    user.coins += 10;
    await saveUser(user, env);
    return json({ ok: true, coins: user.coins, earned: 10 });
  }

  // ── PayPal: get link ──────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/paypal/get-link') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const { package: pkg } = await readBody();
    const packages = {
      starter: { coins: 500,  amount: '5.00'  },
      popular: { coins: 1200, amount: '10.00' },
      premium: { coins: 3000, amount: '20.00' },
    };
    const chosen = packages[pkg];
    if (!chosen) return json({ error: 'Invalid package' }, 400);
    const origin = request.headers.get('Origin') || url.origin;
    const note       = encodeURIComponent(`NUMSE coins:${chosen.coins}:${user.username}`);
    const successUrl = encodeURIComponent(`${origin}/?payment=success&coins=${chosen.coins}&user=${user.username}`);
    const cancelUrl  = encodeURIComponent(`${origin}/?payment=cancelled`);
    const paypalUrl  = `https://www.paypal.com/cgi-bin/webscr?cmd=_xclick`
      + `&business=${encodeURIComponent(PAYPAL_EMAIL)}`
      + `&item_name=${encodeURIComponent('NUMSE ' + chosen.coins + ' Coins')}`
      + `&amount=${chosen.amount}&currency_code=USD`
      + `&return=${successUrl}&cancel_return=${cancelUrl}&custom=${note}`;
    return json({ url: paypalUrl, coins: chosen.coins, amount: chosen.amount });
  }

  // ── PayPal IPN ────────────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/paypal/ipn') {
    const body = await readBody();
    const custom = String(body.custom || '');
    const parts = custom.split(':');
    if (parts[0] === 'NUMSE coins' && parts[1] && parts[2] && body.payment_status === 'Completed') {
      const coins = Number(parts[1]);
      const username = parts[2];
      if (coins > 0) {
        const targetUser = await env.NUMSE_KV.get('user:' + username, 'json');
        if (targetUser) {
          targetUser.coins += coins;
          await saveUser(targetUser, env);
        }
      }
    }
    return json({ ok: true });
  }

  // ── Messages: send ────────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/messages/send') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const body = await readBody();
    const to           = sanitize(body.to);
    const text         = sanitize(body.text);
    const listingId    = sanitize(body.listingId);
    const listingTitle = sanitize(body.listingTitle || '');
    if (!to || !text || !listingId) return json({ error: 'Missing fields' }, 400);
    if (text.length > 1000) return json({ error: 'Message too long' }, 400);
    const toUser = await env.NUMSE_KV.get('user:' + to);
    if (!toUser) return json({ error: 'User not found' }, 404);
    if (to === user.username) return json({ error: "Can't message yourself" }, 400);
    const cid = convId(user.username, to, listingId);
    let conv = await env.NUMSE_KV.get('conv:' + cid, 'json');
    if (!conv) conv = { participants: [user.username, to], listingId, listingTitle, msgs: [] };
    conv.msgs.push({ from: user.username, text, at: Date.now() });
    await env.NUMSE_KV.put('conv:' + cid, JSON.stringify(conv));
    await addUserConv(user.username, cid, env);
    await addUserConv(to, cid, env);
    return json({ ok: true, cid }, 201);
  }

  // ── Messages: list conversations ──────────────────────────────────
  if (method === 'GET' && fullPath === '/api/messages') {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const cids = await getUserConvs(user.username, env);
    const convs = (await Promise.all(cids.map(async cid => {
      const c = await env.NUMSE_KV.get('conv:' + cid, 'json');
      if (!c) return null;
      return {
        cid,
        listingId:    c.listingId,
        listingTitle: c.listingTitle,
        participants: c.participants,
        other:        c.participants.find(u => u !== user.username),
        lastMsg:      c.msgs[c.msgs.length - 1] || null,
        unread:       c.msgs.filter(msg => msg.from !== user.username && !msg.read).length,
      };
    }))).filter(Boolean).sort((a, b) => (b.lastMsg?.at || 0) - (a.lastMsg?.at || 0));
    return json(convs);
  }

  // ── Messages: read conversation ───────────────────────────────────
  // matches /api/messages/{cid} where cid may contain '__'
  if (method === 'GET' && routeParts[0] === 'messages' && routeParts.length > 1) {
    const user = await getUser(authToken(request), env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const cid = decodeURIComponent(routeParts.slice(1).join('/'));
    const conv = await env.NUMSE_KV.get('conv:' + cid, 'json');
    if (!conv) return json({ error: 'Conversation not found' }, 404);
    if (!conv.participants.includes(user.username)) return json({ error: 'Forbidden' }, 403);
    conv.msgs.forEach(msg => { if (msg.from !== user.username) msg.read = true; });
    await env.NUMSE_KV.put('conv:' + cid, JSON.stringify(conv));
    return json(conv);
  }

  // ── Admin: list users ─────────────────────────────────────────────
  if (method === 'GET' && fullPath === '/api/admin/users') {
    const user = await getUser(authToken(request), env);
    if (!user || user.username !== ADMIN_USER) return json({ error: 'Forbidden' }, 403);
    const list = await env.NUMSE_KV.list({ prefix: 'user:' });
    const users = await Promise.all(list.keys.map(k => env.NUMSE_KV.get(k.name, 'json')));
    return json(users.filter(Boolean).map(u => ({ username: u.username, coins: u.coins, joinedAt: u.joinedAt })));
  }

  // ── Admin: give coins ─────────────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/admin/give-coins') {
    const user = await getUser(authToken(request), env);
    if (!user || user.username !== ADMIN_USER) return json({ error: 'Forbidden' }, 403);
    const { target, amount } = await readBody();
    const t = sanitize(target), a = Number(amount);
    if (!t || !a || isNaN(a) || a <= 0 || a > 1000000) return json({ error: 'Invalid request' }, 400);
    const targetUser = await env.NUMSE_KV.get('user:' + t, 'json');
    if (!targetUser) return json({ error: `User "${t}" not found` }, 404);
    targetUser.coins += a;
    await saveUser(targetUser, env);
    return json({ ok: true, newBalance: targetUser.coins });
  }

  // ── Admin: reset user password ────────────────────────────────────
  if (method === 'POST' && fullPath === '/api/admin/reset-user-password') {
    const user = await getUser(authToken(request), env);
    if (!user || user.username !== ADMIN_USER) return json({ error: 'Forbidden' }, 403);
    const { target, newPassword } = await readBody();
    const t = sanitize(target), pw = String(newPassword || '');
    if (!t || pw.length < 6) return json({ error: 'Invalid' }, 400);
    const targetUser = await env.NUMSE_KV.get('user:' + t, 'json');
    if (!targetUser) return json({ error: 'User not found' }, 404);
    targetUser.password = await hashPw(pw);
    await saveUser(targetUser, env);
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}
