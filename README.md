# NUMSE Marketplace — Cloudflare Pages

## What changed from the Render/Node version

| Before (Render) | After (Cloudflare) |
|---|---|
| `server.js` (Node HTTP) | `functions/api/[[route]].js` (Pages Function) |
| In-memory `db` object | **Cloudflare KV** (persistent across requests) |
| Node `crypto` module | Web Crypto API (`crypto.subtle`) |
| `fs.readFileSync('index.html')` | Served automatically as a static asset |
| `process.env.PORT` | Not needed — Pages handles routing |

Sessions are stored in KV with a 7-day TTL and expire automatically.

---

## Deploy in 5 steps

### 1. Install Wrangler
```bash
npm install
```

### 2. Log in to Cloudflare
```bash
npx wrangler login
```

### 3. Create a KV namespace
```bash
npx wrangler kv:namespace create NUMSE_KV
npx wrangler kv:namespace create NUMSE_KV --preview
```
Copy the two IDs printed and paste them into `wrangler.toml`:
```toml
id         = "abc123..."
preview_id = "def456..."
```

### 4. Deploy
```bash
npm run deploy
```
Cloudflare will give you a `*.pages.dev` URL.

### 5. (Optional) Custom domain
In the Cloudflare dashboard → Pages → your project → Custom domains.

---

## Local development
```bash
npm run dev
# → http://localhost:8788
```

---

## KV data model

| Key | Value | Notes |
|---|---|---|
| `user:{username}` | JSON user object | username, hashed password, coins, joinedAt |
| `session:{token}` | JSON session object | username + expiresAt; auto-expires via KV TTL |
| `listings` | JSON array of all listings | Loaded/saved as one blob |
| `conv:{cid}` | JSON conversation object | participants, msgs array |
| `user_convs:{username}` | JSON array of cid strings | Inbox index per user |

---

## Connecting PayPal IPN
Set your PayPal IPN URL to:
```
https://your-project.pages.dev/api/paypal/ipn
```
