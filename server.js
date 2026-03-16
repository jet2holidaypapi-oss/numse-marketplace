const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'db.json');

// --- DATABASE PERSISTENCE ---
function loadDB() {
  if (fs.existsSync(DB_FILE)) {
    try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error("DB Corrupt"); }
  }
  return {
    users: { admin: { username: 'admin', password: hash('admin123'), coins: 99999, joinedAt: Date.now() } },
    listings: [], // Defaults removed
    messages: []  // Chat storage
  };
}

function saveDB() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function hash(str) { return crypto.createHash('sha256').update(str).digest('hex'); }
function uid() { return crypto.randomBytes(6).toString('hex'); }

let db = loadDB();
const sessions = {};

function getUser(token) {
  const username = sessions[token];
  return username ? db.users[username] : null;
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > 10 * 1024 * 1024) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
  });
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS' });
  res.end(JSON.stringify(body));
}

async function router(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method = req.method;
  if (method === 'OPTIONS') return send(res, 200, {});

  // Serve Frontend
  if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const html = fs.readFileSync(path.join(__dirname, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(html);
  }

  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();

  // Auth API
  if (method === 'POST' && pathname === '/api/login') {
    const { username, password } = await readBody(req);
    const user = db.users[username];
    if (!user || user.password !== hash(password)) return send(res, 401, { error: 'Invalid login' });
    const sessionToken = crypto.randomBytes(16).toString('hex');
    sessions[sessionToken] = username;
    return send(res, 200, { token: sessionToken, username, coins: user.coins });
  }

  if (method === 'POST' && pathname === '/api/register') {
    const { username, password } = await readBody(req);
    if (db.users[username]) return send(res, 400, { error: 'Taken' });
    db.users[username] = { username, password: hash(password), coins: 200, joinedAt: Date.now() };
    saveDB();
    const sessionToken = crypto.randomBytes(16).toString('hex');
    sessions[sessionToken] = username;
    return send(res, 201, { token: sessionToken, username, coins: 200 });
  }

  // Listing API
  if (method === 'GET' && pathname === '/api/listings') return send(res, 200, db.listings);
  
  if (method === 'POST' && pathname === '/api/listings') {
    const user = getUser(token);
    if (!user) return send(res, 401, { error: 'Auth required' });
    const body = await readBody(req);
    const item = { id: uid(), seller: user.username, title: body.title, desc: body.desc, price: Number(body.price), category: body.category, image: body.image, createdAt: Date.now() };
    db.listings.push(item);
    saveDB();
    return send(res, 201, item);
  }

  // CHAT API
  if (method === 'GET' && pathname === '/api/messages') {
    const user = getUser(token);
    if (!user) return send(res, 401, { error: 'Auth required' });
    const myMsgs = db.messages.filter(m => m.from === user.username || m.to === user.username);
    return send(res, 200, myMsgs);
  }

  if (method === 'POST' && pathname === '/api/messages') {
    const user = getUser(token);
    if (!user) return send(res, 401, { error: 'Auth required' });
    const { to, text } = await readBody(req);
    const msg = { id: uid(), from: user.username, to, text, at: Date.now() };
    db.messages.push(msg);
    saveDB();
    return send(res, 201, msg);
  }

  // Admin Tools
  if (method === 'POST' && pathname === '/api/admin/give-coins') {
    const user = getUser(token);
    if (!user || user.username !== 'admin') return send(res, 403, { error: 'Admin only' });
    const { target, amount } = await readBody(req);
    if (db.users[target]) { db.users[target].coins += Number(amount); saveDB(); return send(res, 200, { ok: true }); }
    return send(res, 404, { error: 'Not found' });
  }

  if (method === 'DELETE' && pathname.startsWith('/api/listings/')) {
    const user = getUser(token);
    const id = pathname.split('/').pop();
    const idx = db.listings.findIndex(l => l.id === id);
    if (idx > -1 && (user.username === 'admin' || db.listings[idx].seller === user.username)) {
      db.listings.splice(idx, 1);
      saveDB();
      return send(res, 200, { ok: true });
    }
    return send(res, 403, { error: 'Denied' });
  }

  return send(res, 404, { error: 'Not Found' });
}

http.createServer(router).listen(PORT, () => { console.log(`Live on ${PORT}`); });