const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = 'Papi';

function uid() { return crypto.randomBytes(6).toString('hex'); }
function hash(str) { return crypto.createHash('sha256').update(str).digest('hex'); }

let db = {
  users: {},
  listings: [],
  messages: {},  // { conversationId: [ {from, text, at} ] }
  transactions: []
};

// conversationId = sorted pair of usernames + listingId
function convId(a, b, listingId) {
  return [a, b].sort().join('__') + '__' + listingId;
}

const sessions = {};
function createSession(username) {
  const token = crypto.randomBytes(16).toString('hex');
  sessions[token] = username;
  return token;
}
function getUser(token) {
  const username = sessions[token];
  return username ? db.users[username] : null;
}
function authToken(req) {
  return (req.headers['authorization'] || '').replace('Bearer ', '').trim();
}
function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
  });
  res.end(JSON.stringify(body));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', reject);
  });
}

async function router(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;
  const m = req.method;

  if (m === 'OPTIONS') return send(res, 200, {});

  // Serve frontend
  if (m === 'GET' && (p === '/' || p === '/index.html')) {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(html);
  }

  // ── Auth ──
  if (m === 'POST' && p === '/api/register') {
    const { username, password } = await readBody(req);
    if (!username || !password) return send(res, 400, { error: 'Username and password required' });
    if (username.length < 3) return send(res, 400, { error: 'Username must be at least 3 characters' });
    if (db.users[username]) return send(res, 409, { error: 'Username taken' });
    db.users[username] = { username, password: hash(password), coins: 200, joinedAt: Date.now() };
    const token = createSession(username);
    return send(res, 201, { token, username, coins: 200 });
  }

  if (m === 'POST' && p === '/api/login') {
    const { username, password } = await readBody(req);
    const user = db.users[username];
    if (!user || user.password !== hash(password)) return send(res, 401, { error: 'Invalid credentials' });
    const token = createSession(username);
    return send(res, 200, { token, username, coins: user.coins });
  }

  if (m === 'GET' && p === '/api/me') {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    return send(res, 200, { username: user.username, coins: user.coins });
  }

  // ── Listings ──
  if (m === 'GET' && p === '/api/listings') {
    const q = url.searchParams.get('q') || '';
    const cat = url.searchParams.get('category') || '';
    let listings = db.listings.map(l => ({ ...l }));
    if (q) listings = listings.filter(l => l.title.toLowerCase().includes(q.toLowerCase()) || l.desc.toLowerCase().includes(q.toLowerCase()));
    if (cat) listings = listings.filter(l => l.category === cat);
    listings.sort((a, b) => b.createdAt - a.createdAt);
    return send(res, 200, listings);
  }

  if (m === 'POST' && p === '/api/listings') {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const { title, desc, price, category, image } = await readBody(req);
    if (!title) return send(res, 400, { error: 'Title is required' });
    if (!price || isNaN(price) || Number(price) <= 0) return send(res, 400, { error: 'Enter a valid price' });
    const listing = { id: uid(), seller: user.username, title, desc: desc || '', price: Number(price), category: category || 'Other', image: image || null, createdAt: Date.now() };
    db.listings.push(listing);
    return send(res, 201, listing);
  }

  if (m === 'DELETE' && p.startsWith('/api/listings/')) {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const id = p.split('/')[3];
    const idx = db.listings.findIndex(l => l.id === id);
    if (idx === -1) return send(res, 404, { error: 'Listing not found' });
    if (db.listings[idx].seller !== user.username && user.username !== ADMIN_USER) return send(res, 403, { error: 'Not your listing' });
    db.listings.splice(idx, 1);
    return send(res, 200, { ok: true });
  }

  if (m === 'POST' && p.startsWith('/api/buy/')) {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const id = p.split('/')[3];
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

  // ── Messages ──
  // Send a message about a listing
  if (m === 'POST' && p === '/api/messages/send') {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const { to, listingId, listingTitle, text } = await readBody(req);
    if (!to || !text || !listingId) return send(res, 400, { error: 'Missing fields' });
    if (!db.users[to]) return send(res, 404, { error: 'User not found' });
    if (to === user.username) return send(res, 400, { error: "Can't message yourself" });
    const cid = convId(user.username, to, listingId);
    if (!db.messages[cid]) db.messages[cid] = { participants: [user.username, to], listingId, listingTitle: listingTitle || '', msgs: [] };
    db.messages[cid].msgs.push({ from: user.username, text, at: Date.now() });
    return send(res, 201, { ok: true, cid });
  }

  // Get all conversations for current user
  if (m === 'GET' && p === '/api/messages') {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const convs = Object.entries(db.messages)
      .filter(([, c]) => c.participants.includes(user.username))
      .map(([cid, c]) => ({
        cid,
        listingId: c.listingId,
        listingTitle: c.listingTitle,
        participants: c.participants,
        other: c.participants.find(u => u !== user.username),
        lastMsg: c.msgs[c.msgs.length - 1] || null,
        unread: c.msgs.filter(msg => msg.from !== user.username && !msg.read).length
      }))
      .sort((a, b) => (b.lastMsg?.at || 0) - (a.lastMsg?.at || 0));
    return send(res, 200, convs);
  }

  // Get messages in a conversation
  if (m === 'GET' && p.startsWith('/api/messages/')) {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const cid = decodeURIComponent(p.split('/api/messages/')[1]);
    const conv = db.messages[cid];
    if (!conv) return send(res, 404, { error: 'Conversation not found' });
    if (!conv.participants.includes(user.username)) return send(res, 403, { error: 'Forbidden' });
    // Mark as read
    conv.msgs.forEach(msg => { if (msg.from !== user.username) msg.read = true; });
    return send(res, 200, { ...conv });
  }

  // ── Admin ──
  if (m === 'GET' && p === '/api/admin/users') {
    const user = getUser(authToken(req));
    if (!user || user.username !== ADMIN_USER) return send(res, 403, { error: 'Forbidden' });
    const users = Object.values(db.users).map(u => ({ username: u.username, coins: u.coins }));
    return send(res, 200, users);
  }

  if (m === 'POST' && p === '/api/admin/give-coins') {
    const user = getUser(authToken(req));
    if (!user || user.username !== ADMIN_USER) return send(res, 403, { error: 'Forbidden' });
    const { target, amount } = await readBody(req);
    if (!target || !amount || isNaN(amount) || Number(amount) <= 0) return send(res, 400, { error: 'Invalid request' });
    const targetUser = db.users[target];
    if (!targetUser) return send(res, 404, { error: `User "${target}" not found` });
    targetUser.coins += Number(amount);
    return send(res, 200, { ok: true, newBalance: targetUser.coins });
  }

  return send(res, 404, { error: 'Not found' });
}

http.createServer(router).listen(PORT, () => {
  console.log(`\n  🛒  NUMSE Marketplace is running on port ${PORT}\n`);
});
