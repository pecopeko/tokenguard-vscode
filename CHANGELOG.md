# Changelog

All notable changes to **TokenGuard** (`pecopeko.tokenguard`) are documented in this file.

## [1.0.0] — 2026-11-20

### Added
- **Live Status Bar Token & Cost Meter**: Real-time multi-script BPE-calibrated token estimator (English, Code, JSON, Japanese Hiragana/Katakana/Kanji, Chinese, Korean, Emoji) with live input cost across **GPT-5**, **Claude Sonnet 4**, **Gemini 2.5 Pro**, **GPT-4o mini**, **Claude Haiku 4.5**, and **Gemini 2.5 Flash**.
- **One-Click Safe Prompt Copy & Reversible Restore**: Redacts AWS keys, OpenAI/Anthropic/GitHub/Slack/Stripe tokens, PEM private keys, JWTs, credentialed DB URLs, `.env` secrets, emails, IPv4 addresses, Japanese MyNumber (Mod-11 verified), and phone numbers into `[[SECRET_<TAG>_<N>]]` placeholders stored strictly in an in-memory session vault.
- **Live Inline Secret Leak Diagnostics + Quick Fixes**: Real-time editor squiggles with smart ignore for test fixtures, env references, and `tokenguard-ignore` comments, plus one-click Quick Fixes to replace with language-aware env vars, redact in-place, or suppress.
- **Lossless JSON → `@schema` Context Compressor & Expander**: Cuts JSON payload token count by 50–70% with 100% lossless round-trip expansion back to JSON.
- **TokenGuard Pro (Offline Ed25519 License Key)**:
  - **Workspace Context Budget & Cost Report**: Interactive Webview ranking the top token-heavy files (respecting `.gitignore`) with 6-model full-repo cost table.
  - **Pre-Commit / Workspace Secret & PII Audit Report**: Full-repo secret & PII compliance audit with masked previews and one-click Markdown/JSON export.
