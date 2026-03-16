const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;

function uid() { return crypto.randomBytes(6).toString('hex'); }
function hash(str) { return crypto.createHash('sha256').update(str).digest('hex'); }

let db = {
  users: {
    guest: { username: 'guest', password: hash('guest123'), coins: 500, joinedAt: Date.now() }
  },
  listings: [
    { id: uid(), seller: 'guest', title: 'Vintage Leather Jacket', desc: 'Brown, size M. Barely worn.', price: 120, category: 'Clothing', createdAt: Date.now() - 86400000 },
    { id: uid(), seller: 'guest', title: 'Mechanical Keyboard', desc: 'Cherry MX Blue switches, TKL layout.', price: 85, category: 'Electronics', createdAt: Date.now() - 43200000 },
    { id: uid(), seller: 'guest', title: 'Handmade Ceramic Mug', desc: 'Hand-thrown, holds ~12oz. Glazed in forest green.', price: 22, category: 'Home', createdAt: Date.now() }
  ],
  transactions: []
};

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

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => (data += chunk));
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
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

function authToken(req) {
  return (req.headers['authorization'] || '').replace('Bearer ', '').trim();
}

async function router(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method = req.method;

  if (method === 'OPTIONS') return send(res, 200, {});

  if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(html);
  }

  if (method === 'POST' && pathname === '/api/register') {
    const { username, password } = await readBody(req);
    if (!username || !password) return send(res, 400, { error: 'Username and password required' });
    if (username.length < 3) return send(res, 400, { error: 'Username must be at least 3 characters' });
    if (db.users[username]) return send(res, 409, { error: 'Username taken' });
    db.users[username] = { username, password: hash(password), coins: 200, joinedAt: Date.now() };
    const token = createSession(username);
    return send(res, 201, { token, username, coins: 200 });
  }

  if (method === 'POST' && pathname === '/api/login') {
    const { username, password } = await readBody(req);
    const user = db.users[username];
    if (!user || user.password !== hash(password)) return send(res, 401, { error: 'Invalid credentials' });
    const token = createSession(username);
    return send(res, 200, { token, username, coins: user.coins });
  }

  if (method === 'GET' && pathname === '/api/me') {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    return send(res, 200, { username: user.username, coins: user.coins });
  }

  if (method === 'GET' && pathname === '/api/listings') {
    const q = url.searchParams.get('q') || '';
    const cat = url.searchParams.get('category') || '';
    let listings = [...db.listings];
    if (q) listings = listings.filter(l => l.title.toLowerCase().includes(q.toLowerCase()) || l.desc.toLowerCase().includes(q.toLowerCase()));
    if (cat) listings = listings.filter(l => l.category === cat);
    listings.sort((a, b) => b.createdAt - a.createdAt);
    return send(res, 200, listings);
  }

  if (method === 'POST' && pathname === '/api/listings') {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const { title, desc, price, category } = await readBody(req);
    if (!title) return send(res, 400, { error: 'Title is required' });
    if (!price || isNaN(price) || Number(price) <= 0) return send(res, 400, { error: 'Enter a valid price' });
    const listing = { id: uid(), seller: user.username, title, desc: desc || '', price: Number(price), category: category || 'Other', createdAt: Date.now() };
    db.listings.push(listing);
    return send(res, 201, listing);
  }

  if (method === 'DELETE' && pathname.startsWith('/api/listings/')) {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const id = pathname.split('/')[3];
    const idx = db.listings.findIndex(l => l.id === id);
    if (idx === -1) return send(res, 404, { error: 'Listing not found' });
    if (db.listings[idx].seller !== user.username) return send(res, 403, { error: 'Not your listing' });
    db.listings.splice(idx, 1);
    return send(res, 200, { ok: true });
  }

  if (method === 'POST' && pathname.startsWith('/api/buy/')) {
    const user = getUser(authToken(req));
    if (!user) return send(res, 401, { error: 'Not logged in' });
    const id = pathname.split('/')[3];
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

  return send(res, 404, { error: 'Not found' });
}

http.createServer(router).listen(PORT, () => {
  console.log(`\n  🛒  NUMSE Marketplace is running on port ${PORT}\n`);
});
