# TokenGuard — 5-Minute `$0.00` Marketplace Publishing & Pro Monetization Guide

This guide walks you through publishing **`tokenguard-1.0.0.vsix`** to **both** major IDE marketplaces (**$0.00** publisher fees) and enabling automated **$0.00-backend** Pro license key sales via Gumroad, Lemon Squeezy, Stripe Payment Links, or GitHub Sponsors.

---

## Step 0: Rotate to Your Own Issuer Ed25519 Private Key (1 Minute)

Before publishing to the public marketplaces, generate your personal Ed25519 issuer keypair stored strictly **outside** this git repository:

```bash
node tools/keygen.mjs init --out ~/.tokenguard/issuer.private.pem
```

1. Back up `~/.tokenguard/issuer.private.pem` in your password manager (1Password / Bitwarden). **Never commit it to git.**
2. Copy the printed `-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----` block into `DEFAULT_PUBLIC_KEY_PEM` inside `src/core/license.js`.
3. Update `tokenguard.proCheckoutUrl` in `package.json` to your Gumroad / Lemon Squeezy / Stripe Payment Link / GitHub Sponsors URL.
4. Rebuild and verify:

```bash
npm test
npm run package
```

---

## Step 1: Publish to Visual Studio Marketplace (`$0.00` — Serves VS Code)

Visual Studio Marketplace is 100% free to publish extensions.

1. Create a free Microsoft / Azure DevOps account at `https://dev.azure.com` (no credit card required).
2. Generate a Personal Access Token (PAT):
   - Organization: **All accessible organizations**
   - Scope: **Custom defined → Marketplace → Manage**
3. Create your free publisher (`pecopeko`) at `https://marketplace.visualstudio.com/manage`.
4. Upload `tokenguard-1.0.0.vsix` directly via the **Web UI** (`+ New extension → Visual Studio Code → drag & drop tokenguard-1.0.0.vsix`) **or** via CLI:

```bash
npx --yes @vscode/vsce publish --packagePath tokenguard-1.0.0.vsix -p "$VSCE_PAT"
```

Your extension goes live at:
`https://marketplace.visualstudio.com/items?itemName=pecopeko.tokenguard`

---

## Step 2: Publish to Open VSX Registry (`$0.00` — Serves Cursor, Windsurf, Antigravity, VSCodium, Gitpod)

Cursor, Windsurf, VSCodium, and Antigravity pull extensions directly from **Open VSX** (maintained by the Eclipse Foundation — 100% free).

1. Sign in with GitHub at `https://open-vsx.org`.
2. Sign the one-click Eclipse Publisher Agreement in your Open VSX profile and create an Access Token (`OVSX_PAT`).
3. Create namespace & publish your existing `.vsix`:

```bash
npx --yes ovsx create-namespace pecopeko -p "$OVSX_PAT"
npx --yes ovsx publish tokenguard-1.0.0.vsix -p "$OVSX_PAT"
```

Your extension goes live immediately for Cursor & Windsurf users at:
`https://open-vsx.org/extension/pecopeko/tokenguard`

---

## Step 3: `$0.00`-Backend Pro License Key Fulfillment

Because TokenGuard Pro verifies **Ed25519 signatures completely offline**, you pay **$0.00/month** in license servers or databases.

### Recommended Pricing Tiers
- **Pro Monthly**: `$9/month` (`--plan pro-monthly --expires <ISO-date>`)
- **Pro Lifetime**: `$29 one-time` (`--plan pro-lifetime`) — highest indie-dev conversion!
- **Team (10 seats)**: `$149 one-time` (`--plan team --seats 10`)

### Mint a Key Manually (Day 1 — Zero Infrastructure)
```bash
node tools/keygen.mjs sign \
  --key ~/.tokenguard/issuer.private.pem \
  --email buyer@company.com \
  --plan pro-lifetime
```

Verify any minted key locally:
```bash
node tools/keygen.mjs verify \
  --key ~/.tokenguard/issuer.private.pem \
  --license "TGPRO-..."
```

### Zero-Cost Automated Fulfillment Options
1. **Gumroad / Lemon Squeezy Custom Webhook → Free Cloudflare Worker**:
   - Store your Ed25519 private key in a Cloudflare Worker Secret (`wrangler secret put TG_PRIVATE_KEY_PEM`) on the free tier (100,000 req/day `$0.00`).
   - On `sale` webhook, sign the buyer's email into a `TGPRO-...` key using Web Crypto `Ed25519` and return/email it instantly!
2. **Pre-Generated Key Pool on Gumroad / Whop**:
   - Pre-mint a batch of `pro-lifetime` keys (`customer@tokenguard.pro` / unique `id`) and upload them to Gumroad's built-in "Upload your own license keys" field — **zero webhook code required!**
3. **GitHub Sponsors**:
   - Add a `$9/mo` or `$29 one-time` tier on GitHub Sponsors and send the minted `TGPRO-...` key in the sponsor welcome message.

---

## Security Checklist Before Publishing
- [ ] `tools/` and `*.pem` are excluded from `tokenguard-1.0.0.vsix` (enforced automatically by `.vscodeignore` and `scripts/build_vsix.mjs`).
- [ ] `npm test` passes 100%.
- [ ] `unzip -t tokenguard-1.0.0.vsix` reports `No errors detected`.
- [ ] `package.json` `"dependencies"` remains `{}`.
