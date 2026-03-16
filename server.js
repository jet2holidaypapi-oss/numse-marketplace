const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = 'Papi';

const PAYPAL_EMAIL = 'Jet2holidaypapi@gmail.com'; // 100 coins = $1

// ── Security helpers ──────────────────────────────────────────
function uid() { return crypto.randomBytes(8).toString('hex'); }
function hash(str) {
  // PBKDF2 - much stronger than plain SHA256
  return crypto.pbkdf2Sync(str, 'numse_salt_v1', 100000, 64, 'sha512').toString('hex');
}
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, 500).replace(/[<>]/g, '');
}

// ── Rate limiting ─────────────────────────────────────────────
const rateLimits = {}; // ip -> { count, resetAt }
function rateLimit(ip, max = 20, windowMs = 60000) {
  const now = Date.now();
  if (!rateLimits[ip] || rateLimits[ip].resetAt < now) {
    rateLimits[ip] = { count: 1, resetAt: now + windowMs };
    return false;
  }
  rateLimits[ip].count++;
  return rateLimits[ip].count > max;
}
// Strict rate limit for auth routes
function authRateLimit(ip) { return rateLimit(ip, 10, 60000); }
// Ad cooldown per user: 1 ad per 5 minutes
const adCooldowns = {};
function canWatchAd(username) {
  const now = Date.now();
  if (!adCooldowns[username] || adCooldowns[username] < now) {
    adCooldowns[username] = now + 5 * 60 * 1000;
    return true;
  }
  return false;
}

// ── DB ────────────────────────────────────────────────────────
let db = { users: {}, listings: [], messages: {}, transactions: [] };
function convId(a, b, lid) { return [a,b].sort().join('__')+'__'+lid; }

// ── Sessions ──────────────────────────────────────────────────
const sessions = {};
function createSession(username) {
  // Expire old sessions for this user
  Object.keys(sessions).forEach(t => { if (sessions[t].username === username) delete sessions[t]; });
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = { username, createdAt: Date.now(), expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 };
  return token;
}
function getUser(token) {
  if (!token) return null;
  const s = sessions[token];
  if (!s || s.expiresAt < Date.now()) { delete sessions[token]; return null; }
  return db.users[s.username] || null;
}
function authToken(req) { return (req.headers['authorization'] || '').replace('Bearer ','').trim(); }

// ── HTTP helpers ──────────────────────────────────────────────
function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  });
  res.end(JSON.stringify(body));
}
function readBody(req, maxBytes = 5 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) { req.destroy(); return reject(new Error('Body too large')); }
      chunks.push(chunk);
    });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
function getIP(req) { return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown'; }

// ── Router ────────────────────────────────────────────────────
async function router(req, res) {
  try {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const p = url.pathname;
    const m = req.method;
    const ip = getIP(req);

    if (m === 'OPTIONS') return send(res, 200, {});

    // Global rate limit
    if (rateLimit(ip, 120, 60000)) return send(res, 429, { error: 'Too many requests' });

    // Serve frontend
    if (m === 'GET' && (p === '/' || p === '/index.html')) {
      const html = fs.readFileSync(path.join(__dirname, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html', 'X-Frame-Options': 'DENY' });
      return res.end(html);
    }

    // ── Register ──
    if (m === 'POST' && p === '/api/register') {
      if (authRateLimit(ip)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
      const { username, password } = await readBody(req);
      const u = sanitize(username), pw = String(password || '');
      if (!u || !pw) return send(res, 400, { error: 'Username and password required' });
      if (u.length < 3 || u.length > 30) return send(res, 400, { error: 'Username must be 3–30 characters' });
      if (!/^[a-zA-Z0-9_]+$/.test(u)) return send(res, 400, { error: 'Username: letters, numbers, underscores only' });
      if (pw.length < 6) return send(res, 400, { error: 'Password must be at least 6 characters' });
      if (db.users[u]) return send(res, 409, { error: 'Username taken' });
      db.users[u] = { username: u, password: hash(pw), coins: 200, joinedAt: Date.now() };
      const token = createSession(u);
      return send(res, 201, { token, username: u, coins: 200 });
    }

    // ── Login ──
    if (m === 'POST' && p === '/api/login') {
      if (authRateLimit(ip)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
      const { username, password } = await readBody(req);
      const u = sanitize(username), pw = String(password || '');
      const user = db.users[u];
      // Constant-time compare to prevent timing attacks
      const expectedHash = user ? user.password : hash('dummy_prevent_timing');
      const actualHash = hash(pw);
      const match = crypto.timingSafeEqual(Buffer.from(expectedHash,'hex'), Buffer.from(actualHash,'hex'));
      if (!user || !match) return send(res, 401, { error: 'Invalid username or password' });
      const token = createSession(u);
      return send(res, 200, { token, username: u, coins: user.coins });
    }

    // ── Me ──
    if (m === 'GET' && p === '/api/me') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      return send(res, 200, { username: user.username, coins: user.coins });
    }

    // ── Reset password (must be logged in) ──
    if (m === 'POST' && p === '/api/reset-password') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'You must be logged in to reset your password' });
      const { newPassword } = await readBody(req);
      const pw = String(newPassword || '');
      if (pw.length < 6) return send(res, 400, { error: 'New password must be at least 6 characters' });
      user.password = hash(pw);
      // Invalidate all other sessions for security
      Object.keys(sessions).forEach(t => {
        if (sessions[t].username === user.username && t !== authToken(req)) delete sessions[t];
      });
      return send(res, 200, { ok: true });
    }

    // ── Listings ──
    if (m === 'GET' && p === '/api/listings') {
      const q = sanitize(url.searchParams.get('q') || '');
      const cat = sanitize(url.searchParams.get('category') || '');
      let listings = db.listings.map(l => ({ ...l, image: l.image ? l.image : null }));
      if (q) listings = listings.filter(l => l.title.toLowerCase().includes(q.toLowerCase()) || l.desc.toLowerCase().includes(q.toLowerCase()));
      if (cat) listings = listings.filter(l => l.category === cat);
      listings.sort((a, b) => b.createdAt - a.createdAt);
      return send(res, 200, listings);
    }

    if (m === 'POST' && p === '/api/listings') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const body = await readBody(req);
      const title = sanitize(body.title), desc = sanitize(body.desc || '');
      const price = Number(body.price), category = sanitize(body.category || 'Other');
      const image = typeof body.image === 'string' && body.image.startsWith('data:image/') ? body.image : null;
      if (!title) return send(res, 400, { error: 'Title is required' });
      if (title.length > 100) return send(res, 400, { error: 'Title too long' });
      if (!price || isNaN(price) || price <= 0 || price > 1000000) return send(res, 400, { error: 'Invalid price' });
      const listing = { id: uid(), seller: user.username, title, desc, price, category, image, createdAt: Date.now() };
      db.listings.push(listing);
      return send(res, 201, listing);
    }

    if (m === 'DELETE' && p.startsWith('/api/listings/')) {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const id = sanitize(p.split('/')[3]);
      const idx = db.listings.findIndex(l => l.id === id);
      if (idx === -1) return send(res, 404, { error: 'Listing not found' });
      if (db.listings[idx].seller !== user.username && user.username !== ADMIN_USER) return send(res, 403, { error: 'Not your listing' });
      db.listings.splice(idx, 1);
      return send(res, 200, { ok: true });
    }

    // ── Buy ──
    if (m === 'POST' && p.startsWith('/api/buy/')) {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const id = sanitize(p.split('/')[3]);
      const listing = db.listings.find(l => l.id === id);
      if (!listing) return send(res, 404, { error: 'Listing not found' });
      if (listing.seller === user.username) return send(res, 400, { error: "You can't buy your own listing" });
      if (user.coins < listing.price) return send(res, 400, { error: 'Not enough coins' });
      const seller = db.users[listing.seller];
      user.coins -= listing.price;
      if (seller) seller.coins += listing.price;
      db.listings = db.listings.filter(l => l.id !== id);
      db.transactions.push({ buyer: user.username, seller: listing.seller, item: listing.title, price: listing.price, at: Date.now() });
      return send(res, 200, { ok: true, coins: user.coins });
    }

    // ── Watch ad for coins ──
    if (m === 'POST' && p === '/api/watch-ad') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      user.coins += 10;
      return send(res, 200, { ok: true, coins: user.coins, earned: 10 });
    }

    // ── PayPal: get PayPal link ──
    if (m === 'POST' && p === '/api/paypal/get-link') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const { package: pkg } = await readBody(req);
      const packages = {
        starter: { coins: 500, amount: '5.00' },
        popular: { coins: 1200, amount: '10.00' },
        premium: { coins: 3000, amount: '20.00' }
      };
      const chosen = packages[pkg];
      if (!chosen) return send(res, 400, { error: 'Invalid package' });
      const origin = req.headers.origin || 'http://localhost:' + PORT;
      // Build PayPal.me link — sends user to PayPal to pay, then back to site
      const note = encodeURIComponent(`NUMSE coins:${chosen.coins}:${user.username}`);
      const successUrl = encodeURIComponent(`${origin}/?payment=success&coins=${chosen.coins}&user=${user.username}`);
      const cancelUrl = encodeURIComponent(`${origin}/?payment=cancelled`);
      // PayPal checkout link
      const paypalUrl = `https://www.paypal.com/cgi-bin/webscr?cmd=_xclick&business=${encodeURIComponent(PAYPAL_EMAIL)}&item_name=${encodeURIComponent('NUMSE ' + chosen.coins + ' Coins')}&amount=${chosen.amount}&currency_code=USD&return=${successUrl}&cancel_return=${cancelUrl}&custom=${note}`;
      return send(res, 200, { url: paypalUrl, coins: chosen.coins, amount: chosen.amount });
    }

    // ── PayPal IPN (instant payment notification) ──
    if (m === 'POST' && p === '/api/paypal/ipn') {
      const body = await readBody(req);
      // Parse custom field: coins:username
      const custom = String(body.custom || '');
      const parts = custom.split(':');
      if (parts[0] === 'NUMSE coins' && parts[1] && parts[2]) {
        const coins = Number(parts[1]);
        const username = parts[2];
        if (coins > 0 && db.users[username] && body.payment_status === 'Completed') {
          db.users[username].coins += coins;
          db.transactions.push({ type: 'purchase', username, coins, at: Date.now() });
        }
      }
      return send(res, 200, { ok: true });
    }

    // ── Messages ──
    if (m === 'POST' && p === '/api/messages/send') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const body = await readBody(req);
      const to = sanitize(body.to), text = sanitize(body.text), listingId = sanitize(body.listingId), listingTitle = sanitize(body.listingTitle || '');
      if (!to || !text || !listingId) return send(res, 400, { error: 'Missing fields' });
      if (text.length > 1000) return send(res, 400, { error: 'Message too long' });
      if (!db.users[to]) return send(res, 404, { error: 'User not found' });
      if (to === user.username) return send(res, 400, { error: "Can't message yourself" });
      const cid = convId(user.username, to, listingId);
      if (!db.messages[cid]) db.messages[cid] = { participants: [user.username, to], listingId, listingTitle, msgs: [] };
      db.messages[cid].msgs.push({ from: user.username, text, at: Date.now() });
      return send(res, 201, { ok: true, cid });
    }

    if (m === 'GET' && p === '/api/messages') {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const convs = Object.entries(db.messages)
        .filter(([, c]) => c.participants.includes(user.username))
        .map(([cid, c]) => ({ cid, listingId: c.listingId, listingTitle: c.listingTitle, participants: c.participants, other: c.participants.find(u => u !== user.username), lastMsg: c.msgs[c.msgs.length-1] || null, unread: c.msgs.filter(msg => msg.from !== user.username && !msg.read).length }))
        .sort((a, b) => (b.lastMsg?.at||0) - (a.lastMsg?.at||0));
      return send(res, 200, convs);
    }

    if (m === 'GET' && p.startsWith('/api/messages/')) {
      const user = getUser(authToken(req));
      if (!user) return send(res, 401, { error: 'Not logged in' });
      const cid = decodeURIComponent(p.split('/api/messages/')[1]);
      const conv = db.messages[cid];
      if (!conv) return send(res, 404, { error: 'Conversation not found' });
      if (!conv.participants.includes(user.username)) return send(res, 403, { error: 'Forbidden' });
      conv.msgs.forEach(msg => { if (msg.from !== user.username) msg.read = true; });
      return send(res, 200, { ...conv });
    }

    // ── Admin ──
    if (m === 'GET' && p === '/api/admin/users') {
      const user = getUser(authToken(req));
      if (!user || user.username !== ADMIN_USER) return send(res, 403, { error: 'Forbidden' });
      return send(res, 200, Object.values(db.users).map(u => ({ username: u.username, coins: u.coins, joinedAt: u.joinedAt })));
    }

    if (m === 'POST' && p === '/api/admin/give-coins') {
      const user = getUser(authToken(req));
      if (!user || user.username !== ADMIN_USER) return send(res, 403, { error: 'Forbidden' });
      const { target, amount } = await readBody(req);
      const t = sanitize(target), a = Number(amount);
      if (!t || !a || isNaN(a) || a <= 0 || a > 1000000) return send(res, 400, { error: 'Invalid request' });
      const targetUser = db.users[t];
      if (!targetUser) return send(res, 404, { error: `User "${t}" not found` });
      targetUser.coins += a;
      return send(res, 200, { ok: true, newBalance: targetUser.coins });
    }

    if (m === 'POST' && p === '/api/admin/reset-user-password') {
      const user = getUser(authToken(req));
      if (!user || user.username !== ADMIN_USER) return send(res, 403, { error: 'Forbidden' });
      const { target, newPassword } = await readBody(req);
      const t = sanitize(target), pw = String(newPassword || '');
      if (!t || pw.length < 6) return send(res, 400, { error: 'Invalid' });
      const targetUser = db.users[t];
      if (!targetUser) return send(res, 404, { error: 'User not found' });
      targetUser.password = hash(pw);
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: 'Not found' });
  } catch(err) {
    console.error(err);
    send(res, 500, { error: 'Server error' });
  }
}


http.createServer(router).listen(PORT, () => {
  console.log(`\n  🛒  NUMSE Marketplace running on port ${PORT}`);
  console.log(`  ✅  PayPal payments ready.\n`);
});
