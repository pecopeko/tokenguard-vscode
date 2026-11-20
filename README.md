# TokenGuard — Live AI Token Cost, Secret Leak Shield & Context Compressor

**Stop pasting hardcoded secrets into ChatGPT, Claude, or Cursor — and stop burning 60% extra tokens on bloated JSON.**

**TokenGuard** (`pecopeko.tokenguard`) is a **zero-dependency, 100% local** extension for **VS Code, Cursor, Windsurf, and Antigravity** that solves four daily AI-coding paper cuts right inside your editor with zero telemetry and zero network calls.

---

## Core Free Features (Instant Value, Forever Free)

### 1. Live Status Bar Token & Multi-Model Cost Meter
- Real-time estimated token count for your **active file** or **current selection**, calibrated for **English, Code (`camelCase`/`snake_case`), JSON, Japanese (Hiragana/Katakana/Kanji), Chinese, Korean, and Emoji**.
- Instant estimated input cost for **GPT-5**, **Claude Sonnet 4**, **Gemini 2.5 Pro**, **GPT-4o mini**, **Claude Haiku 4.5**, and **Gemini 2.5 Flash**.
- Click the status bar item anytime to inspect all 6 models and pin your preferred model. Debounced updates = zero editor lag.

### 2. One-Click Safe Prompt Copy + Reversible Restore (`Cmd/Ctrl+Alt+C` / `Cmd/Ctrl+Alt+V`)
- **`TokenGuard: Copy Selection Safely (Redact Secrets & PII)`** scans your selected code/JSON/logs locally for:
  - AWS Access Keys & Secret Keys
  - OpenAI, Anthropic, GitHub, Slack, and Stripe API tokens
  - Private PEM key blocks (`RSA`, `EC`, `OPENSSH`, `PKCS8`)
  - JWTs & credentialed database URLs (`postgres://`, `mongodb+srv://`, `redis://`, `mysql://`, etc.)
  - Hardcoded `.env` / config secrets
  - Emails, non-loopback IPv4 addresses, phone numbers, and **Japanese MyNumber (MIC Mod-11 check-digit verified)**
- Replaces every match with deterministic reversible placeholders (`[[SECRET_AWS_1]]`, `[[SECRET_OPENAI_1]]`, `[[SECRET_EMAIL_1]]`) and keeps the mapping **strictly in an in-memory session vault** (never written to disk).
- Paste safely into ChatGPT, Claude, or Cursor — then run **`TokenGuard: Restore Redacted Tokens from AI Reply`** to restore your real values cleanly!

### 3. Live Inline Secret Leak Squiggles + Quick Fixes
- Automatically highlights hardcoded secrets in active files with smart ignore for test/spec/fixture files, environment variable references (`process.env.*`, `os.environ[...]`), and `// tokenguard-ignore` comments.
- Built-in **Quick Fix** code actions:
  1. Replace hardcoded secret with a language-aware env lookup (`process.env.X`, `os.environ["X"]`, `os.Getenv("X")`, `${X}`)
  2. Redact in-place with a reversible `[[SECRET_...]]` token
  3. Suppress warning on the current line (`tokenguard-ignore`)

### 4. Lossless JSON → Compact Tabular `@schema` Context Compressor (`Cmd/Ctrl+Alt+J`)
- **`TokenGuard: Compress JSON for AI Context (@schema)`** converts repetitive JSON arrays (and wrapper API objects) into compact tabular `@schema v1` format — cutting LLM context token usage by **50–70%**.
- **`TokenGuard: Expand @schema Back to JSON`** restores the exact original JSON with **100% lossless round-trip fidelity** (preserving numbers vs numeric strings, `null`, booleans, missing keys, pipes `|`, newlines, and nested objects).

```text
@schema v1 | id | customer | status | amountUsd
101 | Tanaka | paid | 149.5
102 | Suzuki | pending | 89
```

---

## TokenGuard Pro

Need full-repository visibility before a commit, release, or security audit?

| Feature | Free | TokenGuard Pro ($9/mo or $29 lifetime) |
| --- | :---: | :---: |
| Live Multi-Script Token & 6-Model Cost Meter | Included | Included |
| One-Click Safe Prompt Copy & Reversible Restore | Included | Included |
| Inline Secret Leak Diagnostics + Quick Fixes | Included | Included |
| Lossless JSON ↔ `@schema` Compressor / Expander | Included | Included |
| **Workspace Context Budget & Cost Report** (`.gitignore`-aware full-repo scan, top 25 heaviest files, 6-model cost & context-fit Webview) | — | **Included** |
| **Pre-Commit / Workspace Secret & PII Audit Report** (full-repo scan with masked previews + Markdown/JSON compliance export) | — | **Included** |
| **100% Offline Cryptographic License Verification (Ed25519)** — works air-gapped, zero license server tracking | — | **Included** |

Run **`TokenGuard Pro: Activate / Manage License Key`** from the Command Palette to activate your `TGPRO-...` offline key.

---

## Quick Install (Immediate `.vsix` Install)

Download `tokenguard-1.0.0.vsix` from [GitHub Releases](https://github.com/pecopeko/tokenguard-vscode/releases/latest) and install directly into VS Code, Cursor, or Windsurf:

```bash
# VS Code
code --install-extension tokenguard-1.0.0.vsix

# Cursor
cursor --install-extension tokenguard-1.0.0.vsix

# Windsurf
windsurf --install-extension tokenguard-1.0.0.vsix
```

Or install from the Extensions sidebar: `...` → **Install from VSIX...**

---

## Commands & Shortcuts

| Command | Shortcut (macOS / Win & Linux) |
| --- | --- |
| `TokenGuard: Copy Selection Safely (Redact Secrets & PII)` | `Cmd+Alt+C` / `Ctrl+Alt+C` |
| `TokenGuard: Restore Redacted Tokens from AI Reply` | `Cmd+Alt+V` / `Ctrl+Alt+V` |
| `TokenGuard: Compress JSON for AI Context (@schema)` | `Cmd+Alt+J` / `Ctrl+Alt+J` |
| `TokenGuard: Expand @schema Back to JSON` | Command Palette / Editor Context Menu |
| `TokenGuard: Show Live Token & Multi-Model Cost Breakdown` | Click Status Bar item |
| `TokenGuard: Clear Session Redaction Vault` | Command Palette |
| `TokenGuard Pro: Activate / Manage License Key` | Command Palette |
| `TokenGuard Pro: Workspace Context Budget & Cost Report` | Command Palette |
| `TokenGuard Pro: Pre-Commit / Workspace Secret & PII Audit Report` | Command Palette |

---

## Privacy & Architecture Guarantee

- **Zero Runtime Dependencies**: `dependencies: {}` — pure CommonJS using only Node.js built-in modules (`crypto`, `fs`, `path`).
- **100% Local Execution**: Your code, secrets, PII, and workspace scans **never** leave your machine. Zero telemetry, zero analytics beacons, zero cloud APIs.
- **Offline Ed25519 Pro Licensing**: Only the public verification key ships inside the extension. License checks run completely offline.

## Development & Verification

```bash
# Run full native Node.js test suite
npm test

# Build deterministic OPC .vsix package
npm run package
```

## License

MIT — see [LICENSE](LICENSE).
