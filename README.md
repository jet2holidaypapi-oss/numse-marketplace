# NUMSE Marketplace — Cloudflare Pages

## Deploy via Cloudflare Dashboard (Git-connected)

### Build settings to enter in the Cloudflare Pages dashboard:

| Setting | Value |
|---|---|
| **Framework preset** | None |
| **Build command** | `npx wrangler pages deploy .` |
| **Build output directory** | `.` (a single dot) |
| **Root directory** | `/` (leave blank) |

> ⚠️ Do NOT use `wrangler deploy` — that is for Workers. Pages requires `wrangler pages deploy`.

---

## Deploy via CLI (manual)

```bash
npm install
npx wrangler login
npx wrangler pages deploy .
```

---

## Setting up KV (required for data persistence)

KV must be created and bound **before** deploying.

### Option A — Cloudflare Dashboard
1. Go to Workers & Pages → KV in the sidebar
2. Click "Create namespace" → name it NUMSE_KV
3. Go to your Pages project → Settings → Functions → KV namespace bindings
4. Add binding: Variable name = NUMSE_KV, select your namespace

### Option B — Wrangler CLI
```bash
npx wrangler kv namespace create NUMSE_KV
npx wrangler kv namespace create NUMSE_KV --preview
```
Then paste both IDs into wrangler.toml.

---

## Local development

```bash
npm install
npx wrangler pages dev . --kv NUMSE_KV
# → http://localhost:8788
```

---

## PayPal IPN
Set your IPN URL to: https://your-project.pages.dev/api/paypal/ipn
