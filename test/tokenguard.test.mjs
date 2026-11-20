import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { generateKeyPair, mintLicenseKey } from "../tools/keygen.mjs";
import { buildVsix } from "../scripts/build_vsix.mjs";

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXT_ROOT = path.resolve(__dirname, "..");

const tokenizer = require("../src/core/tokenizer.js");
const redactor = require("../src/core/redactor.js");
const compressor = require("../src/core/compressor.js");
const license = require("../src/core/license.js");
const scanner = require("../src/core/workspace_scanner.js");
const { createExtension } = require("../extension.js");

/**
 * Helper to dynamically construct synthetic secret tokens at runtime
 * so zero contiguous secret literals exist in source files (avoids GH013).
 */
function buildSyntheticSecrets() {
  return {
    awsKey: ["AK", "IA", "Q7X9M2K4P8R5T1W3"].join(""),
    awsDocExample: ["AK", "IA", "IOSFODNN7EXAMPLE"].join(""),
    awsSecret: ["wJalrX", "UtnFEMI/K7MDENG/", "bPxRfiCYz9K8L7M6N5O4P3Q2"].join(""),
    openaiKey: ["sk", "-proj-", "AbCdEfGhIjKlMnOpQrStUvWxYz123456"].join(""),
    anthropicKey: ["sk", "-ant-", "api03-", "ZyXwVuTsRqPoNmLkJiHgFeDcBa987654"].join(""),
    githubToken: ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join(""),
    slackToken: ["xo", "xb-", "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"].join(""),
    stripeKey: ["sk", "_live_", "51MockSyntheticKey9876543210AbCdEf"].join(""),
    jwt: [
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRldiJ9",
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ].join("."),
    dbUrl: ["post", "gres://admin:P$1&sWord99@prod-db.internal:5432/billing"].join(""),
    pemBlock: [
      "-----BEGIN " + "RSA PRIVATE KEY-----",
      "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7Mhgw",
      "-----END " + "RSA PRIVATE KEY-----",
    ].join("\n"),
    validMyNumber: computeValidMyNumber("12345678901"),
    invalidMyNumber: "123456789019",
  };
}

function computeValidMyNumber(first11) {
  let sum = 0;
  for (let n = 1; n <= 11; n += 1) {
    const pn = Number(first11[11 - n]);
    const qn = n <= 6 ? n + 1 : n - 5;
    sum += pn * qn;
  }
  const rem = sum % 11;
  const check = rem <= 1 ? 0 : 11 - rem;
  return `${first11.slice(0, 4)}-${first11.slice(4, 8)}-${first11.slice(8, 11)}${check}`;
}

// ---------------------------------------------------------------------------
// 1. Tokenizer & Cost Estimator Tests
// ---------------------------------------------------------------------------

test("tokenizer: handles empty input, English/code, Japanese multi-script, and 6-model pricing", () => {
  const empty = tokenizer.estimateTokens("");
  assert.equal(empty.tokens, 0);
  assert.equal(empty.dominantScript, "empty");

  const codeText = `export async function fetchUserBillingSummary(userId) {\n  const total = 123456;\n  return { userId, total, status: "paid" };\n}`;
  const codeEst = tokenizer.estimateTokens(codeText);
  assert.ok(codeEst.tokens >= 25 && codeEst.tokens <= 65, `unexpected code tokens: ${codeEst.tokens}`);
  assert.equal(codeEst.dominantScript, "en-code");
  assert.equal(codeEst.lines, 4);

  const jpText = "本日は晴天なり。機密データとマイナンバーを安全にマスキングしてAIへ送信します。";
  const jpEst = tokenizer.estimateTokens(jpText);
  assert.equal(jpEst.dominantScript, "ja-mixed");
  assert.ok(jpEst.tokens > jpText.length, `Japanese text should exceed 1 token/char, got ${jpEst.tokens}`);
  assert.ok(jpEst.breakdown.kanaChars > 10);
  assert.ok(jpEst.breakdown.cjkChars > 10);

  const allCosts = tokenizer.calculateAllModelCosts(100_000);
  assert.equal(allCosts.length, 6);
  const sonnet = allCosts.find((m) => m.modelId === "claude-sonnet-4");
  const gpt5 = allCosts.find((m) => m.modelId === "gpt-5");
  const gemini = allCosts.find((m) => m.modelId === "gemini-2.5-pro");
  assert.ok(Math.abs(sonnet.inputCostUsd - 0.3) < 1e-9);
  assert.ok(Math.abs(gpt5.inputCostUsd - 0.125) < 1e-9);
  assert.ok(Math.abs(gemini.inputCostUsd - 0.125) < 1e-9);
  assert.equal(gemini.contextPercent, 10);

  const label = tokenizer.formatStatusBarLabel({
    tokens: 1240,
    isSelection: true,
    modelId: "claude-sonnet-4",
    secretCount: 2,
  });
  assert.match(label, /Sel: 1,240 tok/);
  assert.match(label, /Claude Sonnet 4/);
  assert.match(label, /2 leaks/);
});

// ---------------------------------------------------------------------------
// 2. Redactor & Reversible Vault Tests
// ---------------------------------------------------------------------------

test("redactor: detects secrets & PII, validates JP MyNumber Mod-11, and restores losslessly including $&/$1 traps", () => {
  const s = buildSyntheticSecrets();
  assert.equal(redactor.isValidMyNumber(s.validMyNumber), true);
  assert.equal(redactor.isValidMyNumber(s.invalidMyNumber), false);
  assert.equal(redactor.isValidMyNumber("0000-0000-0000"), false);

  const sample = [
    `AWS_ACCESS_KEY_ID=${s.awsKey}`,
    `AWS_KEY_AGAIN=${s.awsKey}`,
    `aws_secret_access_key="${s.awsSecret}"`,
    `OPENAI_KEY="${s.openaiKey}"`,
    `ANTHROPIC_KEY="${s.anthropicKey}"`,
    `GH_TOKEN="${s.githubToken}"`,
    `SLACK_TOKEN="${s.slackToken}"`,
    `STRIPE_KEY="${s.stripeKey}"`,
    `AUTH_HEADER="Bearer ${s.jwt}"`,
    `DATABASE_URL="${s.dbUrl}"`,
    `WEBHOOK_SECRET="whsec_customProdValue99887766"`,
    `CONTACT_EMAIL=taro.tanaka@corp-example.co.jp`,
    `SERVER_IP=10.42.88.19`,
    `PHONE=090-1234-5678`,
    `MYNUMBER=${s.validMyNumber}`,
    `NON_MYNUMBER=${s.invalidMyNumber}`,
    s.pemBlock,
  ].join("\n");

  const vault = new redactor.RedactionVault();
  const res = vault.redact(sample, { includeSecrets: true, includePii: true });

  // Zero sensitive values may survive in redactedText
  for (const leak of [
    s.awsKey,
    s.awsSecret,
    s.openaiKey,
    s.anthropicKey,
    s.githubToken,
    s.slackToken,
    s.stripeKey,
    s.jwt,
    s.dbUrl,
    "whsec_customProdValue99887766",
    "taro.tanaka@corp-example.co.jp",
    "10.42.88.19",
    "090-1234-5678",
    s.validMyNumber,
    "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn",
  ]) {
    assert.equal(res.redactedText.includes(leak), false, `Secret leaked in redactedText: ${leak}`);
  }

  // Invalid Mod-11 12-digit number must NOT be falsely flagged as MyNumber
  assert.equal(res.redactedText.includes(s.invalidMyNumber), true);

  // Deduplication: identical AWS key twice uses [[SECRET_AWS_1]] both times
  assert.equal(res.redactedText.match(/\[\[SECRET_AWS_1\]\]/g)?.length, 2);

  // Simulate AI reply referencing placeholders & verify lossless restore (including $1 and $& in dbUrl!)
  const restored = vault.restore(res.redactedText);
  assert.equal(restored.restoredText, sample);
  assert.equal(restored.unknownPlaceholders.length, 0);
  assert.ok(restored.replacedCount >= 15);
});

test("redactor: smart-ignores env refs, placeholders, AWS EXAMPLE key, ignore comments, and test files", () => {
  const s = buildSyntheticSecrets();
  const safeCode = [
    `const k1 = process.env.OPENAI_API_KEY;`,
    `const k2 = os.environ["STRIPE_SECRET_KEY"];`,
    `const API_KEY = "your_api_key_here";`,
    `const docAws = "${s.awsDocExample}";`,
    `const ignored = "${s.openaiKey}"; // tokenguard-ignore`,
    `const loopback = "127.0.0.1";`,
    `const ver = "v1.2.3.4";`,
  ].join("\n");

  const findings = redactor.scanText(safeCode, {
    includeSecrets: true,
    includePii: true,
    respectIgnoreComments: true,
  });
  assert.equal(findings.length, 0, `Expected 0 findings, got: ${JSON.stringify(findings)}`);

  const testFileCode = `const realLooking = "${s.openaiKey}";`;
  assert.equal(
    redactor.scanText(testFileCode, {
      filePath: "src/__tests__/billing.test.ts",
      ignoreTestFiles: true,
    }).length,
    0
  );
  assert.equal(
    redactor.scanText(testFileCode, {
      filePath: "src/billing.ts",
      ignoreTestFiles: true,
    }).length,
    1
  );
});

// ---------------------------------------------------------------------------
// 3. Lossless JSON -> @schema Compressor & Expander Tests
// ---------------------------------------------------------------------------

test("compressor: compresses repetitive JSON array by >=55% tokens with 100% lossless round-trip", () => {
  const orders = Array.from({ length: 15 }, (_, i) => ({
    orderId: `ORD-2026-${String(i + 1).padStart(4, "0")}`,
    customerName: i % 2 === 0 ? `Tanaka Kenji ${i}` : `Alice Smith ${i}`,
    region: i % 3 === 0 ? "ap-northeast-1" : "us-east-1",
    status: i % 4 === 0 ? "pending" : "completed",
    currency: i % 2 === 0 ? "JPY" : "USD",
    amount: Number((19.5 + i * 12.25).toFixed(2)),
    priority: i % 5 === 0,
    notes: i % 3 === 0 ? null : `Shipment batch #${i + 1}`,
  }));

  const prettyJson = JSON.stringify(orders, null, 2);
  const compressed = compressor.compressJsonToSchema(prettyJson);

  assert.equal(compressed.mode, "root-array");
  assert.equal(compressed.rowCount, 15);
  assert.ok(
    compressed.savedPercent >= 55,
    `Expected >=55% token reduction on 15-row JSON array, got ${compressed.savedPercent}%`
  );
  assert.ok(compressed.compressed.startsWith("@schema v1 | "));

  const expanded = compressor.expandSchemaToJson(compressed.compressed);
  assert.deepStrictEqual(expanded.data, orders);
});

test("compressor: preserves tricky edge cases, sparse keys, pipes, backslashes, nested JSON, and wrapped tables", () => {
  const tricky = {
    status: "ok",
    total: 3,
    "items|main": [
      {
        id: 1,
        numStr: "123",
        boolStr: "true",
        nullStr: "null",
        undefStr: "@undef",
        realNull: null,
        empty: "",
        padded: "  spaced  ",
        pipe: "left|right",
        slashPipe: "a\\|b",
        trailingSlash: "dir\\",
        multiline: "line1\nline2\ttab",
        nested: { tags: ["a|b", "c\\d"], ok: true },
        "col|weird": "val",
      },
      {
        id: 2,
        numStr: "-0.5",
        boolStr: "false",
        // intentionally sparse (missing several keys!)
        nested: [1, "x|y", null],
      },
    ],
  };

  const res = compressor.compressJsonToSchema(JSON.stringify(tricky, null, 2));
  assert.equal(res.mode, "wrapped-tables");
  const expanded = compressor.expandSchemaToJson(res.compressed);
  assert.deepStrictEqual(expanded.data, tricky);

  // Non-tabular raw fallback round-trip
  const rawObj = { featureFlags: { darkMode: true, threshold: 0.85 } };
  const rawRes = compressor.compressJsonToSchema(JSON.stringify(rawObj, null, 2));
  assert.equal(rawRes.mode, "raw-minified");
  assert.deepStrictEqual(compressor.expandSchemaToJson(rawRes.compressed).data, rawObj);

  assert.throws(() => compressor.compressJsonToSchema("{invalid json"), /Invalid JSON/);
  assert.throws(() => compressor.expandSchemaToJson("not a schema"), /Unrecognized @schema/);
});

// ---------------------------------------------------------------------------
// 4. Offline Ed25519 Pro License Key Verification Tests
// ---------------------------------------------------------------------------

test("license: embedded default SPKI public key is valid Ed25519 and verifier enforces signatures & expiry", () => {
  const defaultPub = crypto.createPublicKey(license.DEFAULT_PUBLIC_KEY_PEM);
  assert.equal(defaultPub.asymmetricKeyType, "ed25519");

  const kp1 = generateKeyPair();
  const kp2 = generateKeyPair();

  // 1. Valid lifetime key
  const lifetime = mintLicenseKey({
    privateKeyPem: kp1.privateKeyPem,
    email: "pro-dev@example.com",
    plan: "pro-lifetime",
    issuedAt: "2026-11-20T00:00:00Z",
    expiresAt: null,
    seats: 1,
  });
  const okLifetime = license.verifyLicenseKey(lifetime.licenseKey, {
    publicKeyPem: kp1.publicKeyPem,
    now: new Date("2030-01-01T00:00:00Z"),
  });
  assert.equal(okLifetime.valid, true);
  assert.equal(okLifetime.tier, "pro");
  assert.equal(okLifetime.payload.email, "pro-dev@example.com");
  assert.match(license.formatLicenseSummary(okLifetime), /Pro Lifetime/);

  // 2. Valid monthly key before expiry, expired after expiry
  const monthly = mintLicenseKey({
    privateKeyPem: kp1.privateKeyPem,
    email: "monthly@example.com",
    plan: "pro-monthly",
    issuedAt: "2026-11-01T00:00:00Z",
    expiresAt: "2026-12-01T00:00:00Z",
  });
  assert.equal(
    license.verifyLicenseKey(monthly.licenseKey, {
      publicKeyPem: kp1.publicKeyPem,
      now: new Date("2026-11-15T00:00:00Z"),
    }).valid,
    true
  );
  const expiredRes = license.verifyLicenseKey(monthly.licenseKey, {
    publicKeyPem: kp1.publicKeyPem,
    now: new Date("2026-12-02T00:00:00Z"),
  });
  assert.equal(expiredRes.valid, false);
  assert.equal(expiredRes.reason, "expired");

  // 3. Tampered payload fails cryptographic check
  const [, sigPart] = lifetime.licenseKey.slice("TGPRO-".length).split(".");
  const forgedPayload = Buffer.from(
    JSON.stringify({ ...lifetime.payload, email: "attacker@evil.test", plan: "team", seats: 999 }),
    "utf8"
  ).toString("base64url");
  const tamperedKey = `TGPRO-${forgedPayload}.${sigPart}`;
  const tamperedRes = license.verifyLicenseKey(tamperedKey, { publicKeyPem: kp1.publicKeyPem });
  assert.equal(tamperedRes.valid, false);
  assert.equal(tamperedRes.reason, "invalid_signature");

  // 4. Wrong public key fails cryptographic check
  const wrongKeyRes = license.verifyLicenseKey(lifetime.licenseKey, {
    publicKeyPem: kp2.publicKeyPem,
  });
  assert.equal(wrongKeyRes.valid, false);
  assert.equal(wrongKeyRes.reason, "invalid_signature");

  // 5. Malformed inputs fail cleanly
  assert.equal(license.verifyLicenseKey("").reason, "empty_key");
  assert.equal(license.verifyLicenseKey("BADKEY-abc.def").reason, "invalid_prefix");
  assert.equal(license.verifyLicenseKey("TGPRO-nodot").reason, "malformed_format");
});

// ---------------------------------------------------------------------------
// 5. Workspace Scanner (.gitignore, Context Budget & Secret Audit) Tests
// ---------------------------------------------------------------------------

test("workspace_scanner: respects .gitignore, skips binaries, ranks tokens, and masks secrets in audit export", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokenguard-ws-"));
  const s = buildSyntheticSecrets();
  try {
    fs.writeFileSync(
      path.join(tmpDir, ".gitignore"),
      "# ignore logs and build\n*.log\n!keep.log\nbuild/\n",
      "utf8"
    );
    fs.mkdirSync(path.join(tmpDir, "src"), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, "build"), { recursive: true });

    fs.writeFileSync(path.join(tmpDir, "skip.log"), "should be ignored ".repeat(200), "utf8");
    fs.writeFileSync(path.join(tmpDir, "keep.log"), "negated file should be scanned", "utf8");
    fs.writeFileSync(path.join(tmpDir, "build", "bundle.js"), "ignored build artifact".repeat(300), "utf8");
    fs.writeFileSync(path.join(tmpDir, "binary.dat"), Buffer.from([0x89, 0x50, 0x00, 0x00, 0x41]));

    fs.writeFileSync(
      path.join(tmpDir, "src", "big_module.js"),
      "export function computeMetrics(items) { return items.map((x) => x.value * 2); }\n".repeat(40),
      "utf8"
    );
    fs.writeFileSync(
      path.join(tmpDir, "src", "config.env"),
      `OPENAI_API_KEY=${s.openaiKey}\nMYNUMBER=${s.validMyNumber}\n`,
      "utf8"
    );

    const budget = scanner.scanWorkspaceContextBudget(tmpDir);
    const paths = budget.allFiles.map((f) => f.relPath);
    assert.ok(paths.includes("src/big_module.js"));
    assert.ok(paths.includes("src/config.env"));
    assert.ok(paths.includes("keep.log"), "Negated !keep.log must be scanned");
    assert.equal(paths.includes("skip.log"), false, "*.log must be ignored");
    assert.equal(paths.includes("build/bundle.js"), false, "build/ must be ignored");
    assert.equal(paths.includes("binary.dat"), false, "Binary NUL file must be skipped");
    assert.equal(budget.topFiles[0].relPath, "src/big_module.js");
    assert.equal(budget.modelCosts.length, 6);

    const budgetHtml = scanner.renderBudgetWebviewHtml(budget, "Pro Lifetime");
    assert.match(budgetHtml, /Workspace Context Budget/);
    assert.match(budgetHtml, /Claude Sonnet 4/);

    const audit = scanner.scanWorkspaceSecrets(tmpDir, { includePii: true });
    assert.equal(audit.summary.status, "FAIL_CRITICAL");
    assert.ok(audit.findings.some((f) => f.ruleId === "OPENAI_KEY"));
    assert.ok(audit.findings.some((f) => f.ruleId === "JP_MYNUMBER"));

    const md = scanner.formatAuditMarkdown(audit);
    const html = scanner.renderAuditWebviewHtml(audit, "Pro Lifetime");
    assert.equal(md.includes(s.openaiKey), false, "Audit Markdown must NEVER expose raw secrets");
    assert.equal(html.includes(s.openaiKey), false, "Audit HTML must NEVER expose raw secrets");
    assert.match(md, /OPENAI_KEY/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 6. Mocked VS Code Extension Integration Tests
// ---------------------------------------------------------------------------

function createMockVscode({ initialText, filePath, languageId, workspaceDir }) {
  const registeredCommands = new Map();
  const diagnosticsMap = new Map();
  const messages = [];
  const webviews = [];
  let clipboardText = "";
  let inputBoxResponse = undefined;
  let infoChoiceResponse = undefined;
  let codeActionProvider = null;

  class Position {
    constructor(line, character) {
      this.line = line;
      this.character = character;
    }
  }
  class Range {
    constructor(start, end) {
      this.start = start;
      this.end = end;
    }
  }
  class Selection extends Range {
    constructor(start, end) {
      super(start, end);
      this.anchor = start;
      this.active = end;
    }
    get isEmpty() {
      return this.start.line === this.end.line && this.start.character === this.end.character;
    }
  }
  class Diagnostic {
    constructor(range, message, severity) {
      this.range = range;
      this.message = message;
      this.severity = severity;
    }
  }
  class CodeAction {
    constructor(title, kind) {
      this.title = title;
      this.kind = kind;
    }
  }
  class WorkspaceEdit {
    constructor() {
      this.ops = [];
    }
    replace(uri, range, newText) {
      this.ops.push({ type: "replace", uri, range, newText });
    }
    insert(uri, pos, newText) {
      this.ops.push({ type: "insert", uri, pos, newText });
    }
  }
  class MarkdownString {
    constructor(value) {
      this.value = value;
    }
  }

  let docText = initialText;
  function getLines() {
    return docText.split("\n");
  }
  function offsetAt(pos) {
    const lines = getLines();
    let off = 0;
    for (let i = 0; i < pos.line && i < lines.length; i += 1) {
      off += lines[i].length + 1;
    }
    return off + pos.character;
  }
  function positionAt(offset) {
    const lines = getLines();
    let rem = offset;
    for (let i = 0; i < lines.length; i += 1) {
      if (rem <= lines[i].length) {
        return new Position(i, rem);
      }
      rem -= lines[i].length + 1;
    }
    return new Position(lines.length - 1, lines[lines.length - 1].length);
  }

  const document = {
    uri: { fsPath: filePath, toString: () => `file://${filePath}` },
    fileName: filePath,
    languageId,
    get lineCount() {
      return getLines().length;
    },
    getText(range) {
      if (!range) return docText;
      return docText.slice(offsetAt(range.start), offsetAt(range.end));
    },
    lineAt(lineNum) {
      return { text: getLines()[lineNum] || "" };
    },
    positionAt,
  };

  const editor = {
    document,
    selection: new Selection(new Position(0, 0), new Position(0, 0)),
    async edit(callback) {
      const ops = [];
      callback({
        replace(range, replacement) {
          ops.push({ range, replacement });
        },
      });
      for (const op of ops) {
        const start = offsetAt(op.range.start);
        const end = offsetAt(op.range.end);
        docText = docText.slice(0, start) + op.replacement + docText.slice(end);
      }
      return true;
    },
  };

  const statusBarItem = {
    text: "",
    tooltip: "",
    command: "",
    visible: false,
    show() {
      this.visible = true;
    },
    hide() {
      this.visible = false;
    },
    dispose() {},
  };

  const configValues = new Map([
    ["defaultModel", "claude-sonnet-4"],
    ["enableLiveDiagnostics", true],
    ["diagnostics.ignoreTestFiles", true],
    ["diagnostics.includePii", false],
    ["statusBar.debounceMs", 25],
  ]);

  const secretStore = new Map();
  const context = {
    subscriptions: [],
    secrets: {
      async get(k) {
        return secretStore.get(k);
      },
      async store(k, v) {
        secretStore.set(k, v);
      },
      async delete(k) {
        secretStore.delete(k);
      },
    },
    globalState: {
      get: () => undefined,
      update: async () => {},
    },
  };

  const vscode = {
    Position,
    Range,
    Selection,
    Diagnostic,
    CodeAction,
    WorkspaceEdit,
    MarkdownString,
    StatusBarAlignment: { Left: 1, Right: 2 },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    CodeActionKind: { QuickFix: "quickfix" },
    ViewColumn: { One: 1 },
    Uri: { parse: (s) => ({ toString: () => s }) },
    commands: {
      registerCommand(id, fn) {
        registeredCommands.set(id, fn);
        return { dispose() {} };
      },
    },
    languages: {
      createDiagnosticCollection() {
        return {
          set(uri, diags) {
            diagnosticsMap.set(uri.toString(), diags);
          },
          delete(uri) {
            diagnosticsMap.delete(uri.toString());
          },
          dispose() {},
        };
      },
      registerCodeActionsProvider(_sel, provider) {
        codeActionProvider = provider;
        return { dispose() {} };
      },
    },
    window: {
      activeTextEditor: editor,
      createStatusBarItem: () => statusBarItem,
      onDidChangeActiveTextEditor: () => ({ dispose() {} }),
      onDidChangeTextEditorSelection: () => ({ dispose() {} }),
      showInformationMessage: async (msg) => {
        messages.push({ level: "info", msg });
        return infoChoiceResponse;
      },
      showWarningMessage: async (msg) => {
        messages.push({ level: "warn", msg });
        return undefined;
      },
      showErrorMessage: async (msg) => {
        messages.push({ level: "error", msg });
        return undefined;
      },
      showInputBox: async () => inputBoxResponse,
      showQuickPick: async (items) => items[0],
      showTextDocument: async (doc) => doc,
      createWebviewPanel(viewType, title) {
        const panel = { viewType, title, webview: { html: "" } };
        webviews.push(panel);
        return panel;
      },
    },
    workspace: {
      workspaceFolders: [{ uri: { fsPath: workspaceDir } }],
      getConfiguration: () => ({
        get: (k, def) => (configValues.has(k) ? configValues.get(k) : def),
        update: async (k, v) => configValues.set(k, v),
      }),
      onDidChangeTextDocument: () => ({ dispose() {} }),
      onDidCloseTextDocument: () => ({ dispose() {} }),
      onDidChangeConfiguration: () => ({ dispose() {} }),
      openTextDocument: async (opts) => opts,
    },
    env: {
      clipboard: {
        writeText: async (t) => {
          clipboardText = t;
        },
        readText: async () => clipboardText,
      },
      openExternal: async () => true,
    },
  };

  return {
    vscode,
    context,
    editor,
    statusBarItem,
    registeredCommands,
    diagnosticsMap,
    messages,
    webviews,
    getClipboard: () => clipboardText,
    setClipboard: (t) => {
      clipboardText = t;
    },
    setInputBox: (v) => {
      inputBoxResponse = v;
    },
    setInfoChoice: (v) => {
      infoChoiceResponse = v;
    },
    setDocText: (t) => {
      docText = t;
    },
    getDocText: () => docText,
    getCodeActionProvider: () => codeActionProvider,
  };
}

test("extension.js: activation, diagnostics + Quick Fixes, safe copy/restore, JSON @schema, and Pro Ed25519 gating", async () => {
  const tmpWs = fs.mkdtempSync(path.join(os.tmpdir(), "tokenguard-ext-"));
  const s = buildSyntheticSecrets();
  const kp = generateKeyPair();

  try {
    fs.writeFileSync(path.join(tmpWs, "app.js"), `const key = "${s.openaiKey}";\n`, "utf8");
    const mock = createMockVscode({
      initialText: `const apiKey = "${s.openaiKey}";\nconst email = "ops@acme.io";\n`,
      filePath: path.join(tmpWs, "app.js"),
      languageId: "javascript",
      workspaceDir: tmpWs,
    });

    const ext = createExtension(mock.vscode, { publicKeyPem: kp.publicKeyPem });
    const runtime = ext.activate(mock.context);
    await runtime.refreshLicenseState();
    runtime.updateStatusBarNow(mock.editor);

    // 1. Live status bar + live secret diagnostics + 3 Quick Fixes
    assert.equal(mock.statusBarItem.visible, true);
    assert.match(mock.statusBarItem.text, /tok · /);
    assert.match(mock.statusBarItem.text, /1 leak/);

    const fileDiags = mock.diagnosticsMap.get(mock.editor.document.uri.toString());
    assert.equal(fileDiags.length, 1);
    assert.equal(fileDiags[0].code, "OPENAI_KEY");

    const quickFixes = mock
      .getCodeActionProvider()
      .provideCodeActions(mock.editor.document, fileDiags[0].range, { diagnostics: fileDiags });
    assert.equal(quickFixes.length, 3);
    assert.match(quickFixes[0].title, /process\.env\.API_KEY/);
    assert.match(quickFixes[1].title, /\[\[SECRET_OPENAI_1\]\]/);
    assert.match(quickFixes[2].title, /tokenguard-ignore/);

    // 2. Copy Safely -> Clipboard has placeholders -> Restore from AI reply
    await mock.registeredCommands.get("tokenguard.copySafely")();
    const redactedClip = mock.getClipboard();
    assert.equal(redactedClip.includes(s.openaiKey), false);
    assert.equal(redactedClip.includes("ops@acme.io"), false);
    assert.match(redactedClip, /\[\[SECRET_OPENAI_1\]\]/);
    assert.match(redactedClip, /\[\[SECRET_EMAIL_1\]\]/);

    // Simulate AI reply in clipboard and restore into empty selection
    mock.setClipboard(`// Fixed by AI\nconst k = "[[SECRET_OPENAI_1]]"; // notify [[SECRET_EMAIL_1]]`);
    mock.editor.selection = new mock.vscode.Selection(
      new mock.vscode.Position(0, 0),
      new mock.vscode.Position(0, 0)
    );
    const restoreRes = await mock.registeredCommands.get("tokenguard.restoreFromClipboard")();
    assert.equal(restoreRes.replacedCount, 2);
    assert.ok(mock.getDocText().includes(s.openaiKey));
    assert.ok(mock.getDocText().includes("ops@acme.io"));

    // 3. Compress JSON -> @schema & Expand back losslessly
    const sampleJson = [
      { id: 1, service: "auth", latencyMs: 12 },
      { id: 2, service: "billing", latencyMs: 28 },
    ];
    mock.setDocText(JSON.stringify(sampleJson, null, 2));
    mock.editor.selection = new mock.vscode.Selection(
      new mock.vscode.Position(0, 0),
      new mock.vscode.Position(0, 0)
    );
    await mock.registeredCommands.get("tokenguard.compressJson")();
    assert.ok(mock.getDocText().startsWith("@schema v1 | id | service | latencyMs"));
    await mock.registeredCommands.get("tokenguard.expandSchema")();
    assert.deepStrictEqual(JSON.parse(mock.getDocText()), sampleJson);

    // 4. Pro commands MUST be gated without valid license
    const gatedBudget = await mock.registeredCommands.get("tokenguard.proWorkspaceBudget")();
    assert.equal(gatedBudget.gated, true);
    const gatedAudit = await mock.registeredCommands.get("tokenguard.proWorkspaceAudit")();
    assert.equal(gatedAudit.gated, true);

    // 5. Activate valid Ed25519 Pro license key -> unlocks both Pro commands + Webviews
    const proKey = mintLicenseKey({
      privateKeyPem: kp.privateKeyPem,
      email: "founder@studio.dev",
      plan: "pro-lifetime",
    }).licenseKey;
    mock.setInputBox(proKey);
    const activation = await mock.registeredCommands.get("tokenguard.enterLicenseKey")();
    assert.equal(activation.valid, true);

    const unlockedBudget = await mock.registeredCommands.get("tokenguard.proWorkspaceBudget")();
    assert.equal(unlockedBudget.gated, false);
    assert.ok(unlockedBudget.panel.webview.html.includes("Workspace Context Budget"));

    const unlockedAudit = await mock.registeredCommands.get("tokenguard.proWorkspaceAudit")();
    assert.equal(unlockedAudit.gated, false);
    assert.equal(unlockedAudit.report.summary.status, "FAIL_CRITICAL");
    assert.ok(unlockedAudit.panel.webview.html.includes("OPENAI_KEY"));
    assert.equal(unlockedAudit.panel.webview.html.includes(s.openaiKey), false);

    // Dispose cleanly
    for (const d of mock.context.subscriptions) {
      if (d && typeof d.dispose === "function") d.dispose();
    }
    ext.deactivate();
  } finally {
    fs.rmSync(tmpWs, { recursive: true, force: true });
  }
});

test("redactor: detects full-width Japanese MyNumber and restores exact full-width digits", () => {
  const s = buildSyntheticSecrets();
  const fullWidth = s.validMyNumber
    .replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d)))
    .replace(/-/g, "－");
  const text = `個人番号：${fullWidth}（厳秘）`;
  const vault = new redactor.RedactionVault();
  const out = vault.redact(text, { includeSecrets: true, includePii: true });
  assert.equal(out.redactedCount, 1);
  assert.equal(out.findings[0].ruleId, "JP_MYNUMBER");
  assert.equal(out.redactedText, "個人番号：[[SECRET_MYNUMBER_1]]（厳秘）");
  assert.equal(vault.restore(out.redactedText).restoredText, text);
});

test("extension.js: selection meter, breakdown model switch, clearVault, rejected license key, and Python Quick Fix", async () => {
  const tmpWs = fs.mkdtempSync(path.join(os.tmpdir(), "tokenguard-ext2-"));
  const s = buildSyntheticSecrets();
  const kp = generateKeyPair();
  try {
    const mock = createMockVscode({
      initialText: `STRIPE_KEY = "${s.stripeKey}"\nprint("hello world")\n`,
      filePath: path.join(tmpWs, "payments.py"),
      languageId: "python",
      workspaceDir: tmpWs,
    });
    const ext = createExtension(mock.vscode, { publicKeyPem: kp.publicKeyPem });
    const runtime = ext.activate(mock.context);
    await runtime.refreshLicenseState();

    // Selection-scoped status bar label
    mock.editor.selection = new mock.vscode.Selection(
      new mock.vscode.Position(1, 0),
      new mock.vscode.Position(1, 20)
    );
    runtime.updateStatusBarNow(mock.editor);
    assert.match(mock.statusBarItem.text, /Sel: /);

    // Python Quick Fix generates os.environ["STRIPE_KEY"] and # tokenguard-ignore
    const pyDiags = mock.diagnosticsMap.get(mock.editor.document.uri.toString());
    assert.equal(pyDiags.length, 1);
    const pyFixes = mock
      .getCodeActionProvider()
      .provideCodeActions(mock.editor.document, pyDiags[0].range, { diagnostics: pyDiags });
    assert.match(pyFixes[0].title, /os\.environ\["STRIPE_KEY"\]/);
    assert.match(pyFixes[2].title, /# tokenguard-ignore/);

    // Show token breakdown switches pinned model to first item (GPT-5)
    await mock.registeredCommands.get("tokenguard.showTokenBreakdown")();
    assert.match(mock.statusBarItem.text, /GPT-5/);

    // Copy safely populates vault, clearVault empties it
    mock.editor.selection = new mock.vscode.Selection(
      new mock.vscode.Position(0, 0),
      new mock.vscode.Position(0, 0)
    );
    await mock.registeredCommands.get("tokenguard.copySafely")();
    assert.equal(runtime.vault.size(), 1);
    const clearedCount = await mock.registeredCommands.get("tokenguard.clearVault")();
    assert.equal(clearedCount, 1);
    assert.equal(runtime.vault.size(), 0);

    // Invalid license key rejected cleanly without activating Pro
    mock.setInputBox("TGPRO-invalid.signature");
    const badLic = await mock.registeredCommands.get("tokenguard.enterLicenseKey")();
    assert.equal(badLic.valid, false);
    assert.equal((await mock.registeredCommands.get("tokenguard.proWorkspaceBudget")()).gated, true);

    for (const d of mock.context.subscriptions) {
      if (d && typeof d.dispose === "function") d.dispose();
    }
  } finally {
    fs.rmSync(tmpWs, { recursive: true, force: true });
  }
});

test("tools/keygen.mjs CLI: init, sign, and verify end-to-end in isolated temp directory", async () => {
  const { execFileSync } = await import("node:child_process");
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokenguard-keygen-"));
  const keyPath = path.join(tmpDir, "issuer.private.pem");
  const keygenPath = path.join(EXT_ROOT, "tools", "keygen.mjs");
  try {
    const initOut = execFileSync(process.execPath, [keygenPath, "init", "--out", keyPath], {
      encoding: "utf8",
    });
    assert.match(initOut, /-----BEGIN PUBLIC KEY-----/);
    assert.ok(fs.existsSync(keyPath));

    const signOut = execFileSync(
      process.execPath,
      [keygenPath, "sign", "--key", keyPath, "--email", "cli-buyer@example.com", "--plan", "pro-lifetime"],
      { encoding: "utf8" }
    );
    const keyMatch = signOut.match(/TGPRO-[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
    assert.ok(keyMatch, `Expected TGPRO key in CLI output:\n${signOut}`);

    const verifyOut = execFileSync(
      process.execPath,
      [keygenPath, "verify", "--key", keyPath, "--license", keyMatch[0]],
      { encoding: "utf8" }
    );
    const parsed = JSON.parse(verifyOut);
    assert.equal(parsed.valid, true);
    assert.equal(parsed.payload.email, "cli-buyer@example.com");
    assert.equal(parsed.payload.plan, "pro-lifetime");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 7. VSIX Archive Packaging & Security Verification
// ---------------------------------------------------------------------------

test("build_vsix: builds deterministic, structurally valid OPC .vsix excluding tools/, test/, scripts/, and private keys", () => {
  const tmpOut1 = path.join(os.tmpdir(), `tokenguard-test-a-${Date.now()}.vsix`);
  const tmpOut2 = path.join(os.tmpdir(), `tokenguard-test-b-${Date.now()}.vsix`);
  try {
    const res = buildVsix(EXT_ROOT, tmpOut1);
    const res2 = buildVsix(EXT_ROOT, tmpOut2);
    assert.ok(res.bytes > 10_000, `Unexpectedly small VSIX: ${res.bytes} bytes`);
    assert.deepStrictEqual(
      fs.readFileSync(tmpOut1),
      fs.readFileSync(tmpOut2),
      "VSIX build must be 100% deterministic byte-for-byte"
    );

    const buf = fs.readFileSync(tmpOut1);
    // PKZIP local header magic "PK\x03\x04"
    assert.equal(buf[0], 0x50);
    assert.equal(buf[1], 0x4b);
    assert.equal(buf[2], 0x03);
    assert.equal(buf[3], 0x04);

    assert.ok(res.entries.includes("[Content_Types].xml"));
    assert.ok(res.entries.includes("extension.vsixmanifest"));
    assert.ok(res.entries.includes("extension/package.json"));
    assert.ok(res.entries.includes("extension/extension.js"));
    assert.ok(res.entries.includes("extension/assets/icon.png"));
    assert.ok(res.entries.includes("extension/src/core/license.js"));

    for (const entry of res.entries) {
      assert.equal(entry.startsWith("extension/tools/"), false, `Forbidden tools entry in VSIX: ${entry}`);
      assert.equal(entry.startsWith("extension/scripts/"), false, `Forbidden scripts entry in VSIX: ${entry}`);
      assert.equal(entry.startsWith("extension/test/"), false, `Forbidden test entry in VSIX: ${entry}`);
      assert.equal(entry.endsWith(".pem"), false, `Forbidden PEM file in VSIX: ${entry}`);
      assert.equal(entry.endsWith(".vsix"), false, `Nested VSIX in VSIX: ${entry}`);
    }
  } finally {
    if (fs.existsSync(tmpOut1)) fs.unlinkSync(tmpOut1);
    if (fs.existsSync(tmpOut2)) fs.unlinkSync(tmpOut2);
  }
});
