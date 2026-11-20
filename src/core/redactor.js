"use strict";

/**
 * Local secret & PII detector, reversible redaction vault, and smart-ignore engine.
 * 100% local, zero runtime dependencies, zero network calls.
 */

const FULLWIDTH_MAP = new Map();
for (let i = 0; i < 10; i += 1) {
  FULLWIDTH_MAP.set(String.fromCharCode(0xff10 + i), String(i));
}
FULLWIDTH_MAP.set("－", "-");
FULLWIDTH_MAP.set("−", "-");
FULLWIDTH_MAP.set("‐", "-");
FULLWIDTH_MAP.set("‒", "-");
FULLWIDTH_MAP.set("–", "-");
FULLWIDTH_MAP.set("—", "-");
FULLWIDTH_MAP.set("―", "-");
FULLWIDTH_MAP.set("\u3000", " ");

/**
 * Strictly 1-to-1 normalization so character indices stay aligned with original text.
 *
 * @param {string} text
 * @returns {string}
 */
function normalize1To1(text) {
  let out = "";
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    out += FULLWIDTH_MAP.get(ch) || ch;
  }
  return out;
}

/**
 * Validate 12-digit Japanese Individual Number (MyNumber) via MIC Mod-11 check digit.
 *
 * @param {string} raw
 * @returns {boolean}
 */
function isValidMyNumber(raw) {
  const digits = normalize1To1(String(raw || "")).replace(/[\s-]/g, "");
  if (!/^\d{12}$/.test(digits)) {
    return false;
  }
  // Reject trivial all-identical digits (e.g. 000000000000)
  if (/^(\d)\1{11}$/.test(digits)) {
    return false;
  }
  const checkDigit = Number(digits[11]);
  let weightedSum = 0;
  for (let n = 1; n <= 11; n += 1) {
    const pn = Number(digits[11 - n]);
    const qn = n <= 6 ? n + 1 : n - 5;
    weightedSum += pn * qn;
  }
  const rem = weightedSum % 11;
  const expected = rem <= 1 ? 0 : 11 - rem;
  return checkDigit === expected;
}

/**
 * Check if a candidate IPv4 address has valid octets and is non-trivial.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isSensitiveIpv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return false;
  }
  const nums = [];
  for (let i = 0; i < 4; i += 1) {
    const seg = parts[i];
    if (seg.length > 1 && seg.startsWith("0")) {
      return false;
    }
    const n = Number(seg);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      return false;
    }
    nums.push(n);
  }
  // Ignore common loopback, unspecified, broadcast, and RFC 5737 doc-only examples if needed
  if (
    ip === "0.0.0.0" ||
    ip === "127.0.0.1" ||
    ip === "255.255.255.255" ||
    ip === "255.255.255.0" ||
    ip === "1.1.1.1" ||
    ip === "8.8.8.8" ||
    ip === "8.8.4.4"
  ) {
    return false;
  }
  return true;
}

/**
 * Determine if a file path appears to be a test, spec, mock, or fixture file.
 *
 * @param {string} filePath
 * @returns {boolean}
 */
function isLikelyTestOrFixturePath(filePath) {
  if (!filePath || typeof filePath !== "string") {
    return false;
  }
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return (
    /(?:^|\/)(?:__tests__|__mocks__|tests?|specs?|fixtures?|mocks?|testdata|examples?)\//.test(normalized) ||
    /\.(?:test|spec|mock|fixture)\.[a-z0-9]+$/.test(normalized)
  );
}

/**
 * Check whether a line explicitly opts out of secret diagnostics.
 *
 * @param {string} line
 * @returns {boolean}
 */
function hasIgnoreDirective(line) {
  return /(?:tokenguard-ignore|tokenguard-disable-line|pragma:\s*allowlist\s+secret|noscan)/i.test(line);
}

/**
 * Filter obvious environment variable references, already-redacted tokens, and dummy placeholders.
 *
 * @param {string} value
 * @returns {boolean}
 */
function isLikelyPlaceholderOrEnvRef(value) {
  if (!value) {
    return true;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return true;
  }
  if (/^\[\[SECRET_[A-Z0-9_]+_\d+\]\]$/.test(trimmed)) {
    return true;
  }
  if (
    /^(?:process\.env\.[A-Za-z0-9_]+|import\.meta\.env\.[A-Za-z0-9_]+|os\.environ(?:\[|\.get)|os\.getenv|env\.[A-Za-z0-9_]+|\$\{[A-Za-z0-9_:-]+\}|\$[A-Z][A-Z0-9_]+|<[^>]+>|\{\{[^}]+\}\})$/.test(
      trimmed
    )
  ) {
    return true;
  }
  // Obvious dummy / placeholder strings
  if (
    /(?:your[_-]?(?:api|secret|access|auth)?[_-]?(?:key|token|password|secret)|replace[_-]?me|change[_-]?me|placeholder|example[_-]?key|dummy[_-]?(?:key|secret|token)|fake[_-]?(?:key|secret|token)|redacted|not[_-]?a[_-]?secret|insert[_-]?here|todo|xxxx{2,}|000000{2,}|\*{4,})/i.test(
      trimmed
    )
  ) {
    return true;
  }
  // Very low entropy repeated single char (e.g. "aaaaaaaaaaaaaaaaaaaa")
  if (/^(.)\1{7,}$/.test(trimmed)) {
    return true;
  }
  return false;
}

const RULES = [
  {
    id: "PRIVATE_KEY",
    tag: "PEM_KEY",
    kind: "secret",
    severity: "critical",
    priority: 1,
    description: "Private cryptographic PEM key block",
    regex:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    id: "DB_URL",
    tag: "DB_URL",
    kind: "secret",
    severity: "critical",
    priority: 2,
    description: "Database or broker connection string with embedded credentials",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|sqlserver):\/\/[^:\s/@'"]+?:[^@\s/'"]+?@[^\s'"`<>)]+/g,
    validate: (matchText) => {
      const creds = matchText.split("://")[1]?.split("@")[0] || "";
      const pass = creds.split(":").slice(1).join(":");
      return pass.length >= 3 && !isLikelyPlaceholderOrEnvRef(pass);
    },
  },
  {
    id: "AWS_KEY",
    tag: "AWS",
    kind: "secret",
    severity: "critical",
    priority: 3,
    description: "AWS Access Key ID",
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    validate: (matchText) => !matchText.endsWith("EXAMPLE"),
  },
  {
    id: "AWS_SECRET",
    tag: "AWS_SECRET",
    kind: "secret",
    severity: "critical",
    priority: 4,
    description: "AWS Secret Access Key",
    regex:
      /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    captureGroup: 1,
    validate: (val) => !isLikelyPlaceholderOrEnvRef(val) && /[A-Za-z]/.test(val) && /[0-9/+=]/.test(val),
  },
  {
    id: "ANTHROPIC_KEY",
    tag: "ANTHROPIC",
    kind: "secret",
    severity: "critical",
    priority: 5,
    description: "Anthropic API Key",
    regex: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}\b/g,
    validate: (val) => !isLikelyPlaceholderOrEnvRef(val),
  },
  {
    id: "OPENAI_KEY",
    tag: "OPENAI",
    kind: "secret",
    severity: "critical",
    priority: 6,
    description: "OpenAI API Key",
    regex: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    validate: (val) => !isLikelyPlaceholderOrEnvRef(val) && !/^sk-[a-z]+-[a-z]+$/i.test(val),
  },
  {
    id: "GITHUB_TOKEN",
    tag: "GITHUB",
    kind: "secret",
    severity: "critical",
    priority: 7,
    description: "GitHub Personal Access or Fine-Grained Token",
    regex: /\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b/g,
    validate: (val) => !isLikelyPlaceholderOrEnvRef(val),
  },
  {
    id: "SLACK_TOKEN",
    tag: "SLACK",
    kind: "secret",
    severity: "high",
    priority: 8,
    description: "Slack API Token or Incoming Webhook",
    regex:
      /\bxox[baprs]-[0-9A-Za-z-]{10,}\b|https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
    validate: (val) => !isLikelyPlaceholderOrEnvRef(val),
  },
  {
    id: "STRIPE_KEY",
    tag: "STRIPE",
    kind: "secret",
    severity: "critical",
    priority: 9,
    description: "Stripe Secret or Restricted API Key",
    regex: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b/g,
    validate: (val) => !isLikelyPlaceholderOrEnvRef(val),
  },
  {
    id: "JWT",
    tag: "JWT",
    kind: "secret",
    severity: "high",
    priority: 10,
    description: "JSON Web Token (JWT)",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    id: "ENV_SECRET",
    tag: "ENV_SECRET",
    kind: "secret",
    severity: "high",
    priority: 15,
    description: "Hardcoded secret/token/password assignment",
    regex:
      /(?:^|[\s{,])['"]?(?:[A-Z0-9_]*(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|WEBHOOK_SECRET|SIGNING_SECRET|ENCRYPTION_KEY|PRIVATE_TOKEN|DB_PASSWORD|DATABASE_PASSWORD|SMTP_PASSWORD)|(?:apiKey|secretKey|accessToken|authToken|clientSecret|webhookSecret|signingSecret|dbPassword|privateToken))['"]?\s*[:=]\s*(?:['"]([^'"\r\n]{8,256})['"]|([^\s#'",;}\])]{8,256}))/gm,
    captureGroup: "firstNonEmpty",
    validate: (val) => {
      if (isLikelyPlaceholderOrEnvRef(val)) {
        return false;
      }
      // Require non-trivial secret look (mix of chars or length >= 12 without spaces)
      if (/\s/.test(val) && val.length < 16) {
        return false;
      }
      if (/^(?:true|false|null|undefined|localhost|development|production|staging)$/i.test(val)) {
        return false;
      }
      return val.length >= 8;
    },
  },
  {
    id: "JP_MYNUMBER",
    tag: "MYNUMBER",
    kind: "pii",
    severity: "high",
    priority: 20,
    description: "Japanese Individual Number (MyNumber — Mod-11 verified)",
    regex: /(?<!\d[\s-])(?<![A-Za-z0-9])(\d{4}[\s-]?\d{4}[\s-]?\d{4})(?![A-Za-z0-9]|[\s-]\d)/g,
    useNormalized: true,
    validate: (val) => isValidMyNumber(val),
  },
  {
    id: "EMAIL",
    tag: "EMAIL",
    kind: "pii",
    severity: "medium",
    priority: 25,
    description: "Email address",
    regex: /(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9])/g,
    validate: (val) => {
      const lower = val.toLowerCase();
      return !lower.endsWith(".png") && !lower.endsWith(".jpg") && !lower.endsWith(".svg");
    },
  },
  {
    id: "IPV4",
    tag: "IPV4",
    kind: "pii",
    severity: "low",
    priority: 30,
    description: "IPv4 network address",
    regex: /(?<![0-9A-Za-z._-])(\d{1,3}(?:\.\d{1,3}){3})(?![0-9A-Za-z._-])/g,
    validate: (val, text, start) => {
      // Ignore version strings like v1.2.3.4 or version: 1.2.3.4
      const prevChunk = text.slice(Math.max(0, start - 12), start).toLowerCase();
      if (/(?:version|ver|v)\s*[:=]?\s*["']?$/.test(prevChunk)) {
        return false;
      }
      return isSensitiveIpv4(val);
    },
  },
  {
    id: "PHONE",
    tag: "PHONE",
    kind: "pii",
    severity: "medium",
    priority: 35,
    description: "Phone number (JP / International)",
    regex:
      /(?<![0-9A-Za-z-])((?:\+81[\s-]?(?:0)?\d{1,4}[\s-]?\d{1,4}[\s-]?\d{3,4}|0(?:[789]0[\s-]?\d{4}[\s-]?\d{4}|[1-9]\d{0,3}-\d{1,4}-\d{3,4})|\+1[\s-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}|\(\d{3}\)\s?\d{3}-\d{4}))(?![0-9A-Za-z-])/g,
    useNormalized: true,
    validate: (val) => {
      const digits = val.replace(/\D/g, "");
      return digits.length >= 10 && digits.length <= 13;
    },
  },
];

/**
 * Compute 0-based line and column offsets for a character index.
 *
 * @param {number[]} lineStarts
 * @param {number} index
 * @returns {{ line: number, character: number }}
 */
function offsetToPosition(lineStarts, index) {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (lineStarts[mid] <= index) {
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  const line = Math.max(0, hi);
  return { line, character: index - lineStarts[line] };
}

function buildLineIndex(text) {
  const lineStarts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) {
      lineStarts.push(i + 1);
    }
  }
  return lineStarts;
}

function getLineText(text, lineStarts, line) {
  const start = lineStarts[line];
  const end = line + 1 < lineStarts.length ? lineStarts[line + 1] - 1 : text.length;
  return text.slice(start, end);
}

/**
 * Mask a detected secret/PII value for safe display in audit reports.
 *
 * @param {string} value
 * @returns {string}
 */
function maskSecretPreview(value) {
  const clean = String(value || "").replace(/\s+/g, " ");
  if (clean.length <= 8) {
    return "••••••••";
  }
  if (clean.length <= 14) {
    return `${clean.slice(0, 2)}••••${clean.slice(-2)}`;
  }
  return `${clean.slice(0, 4)}••••${clean.slice(-4)}`;
}

/**
 * Suggest a clean environment variable name for Quick Fix replacement.
 *
 * @param {string} ruleId
 * @param {string} lineText
 * @returns {string}
 */
function suggestEnvVarName(ruleId, lineText) {
  const assignMatch = String(lineText || "").match(
    /(?:const|let|var|export)?\s*['"]?([A-Za-z_][A-Za-z0-9_]{2,40})['"]?\s*[:=]/
  );
  if (assignMatch && assignMatch[1]) {
    const raw = assignMatch[1]
      .replace(/([a-z])([A-Z])/g, "$1_$2")
      .toUpperCase()
      .replace(/[^A-Z0-9_]/g, "_");
    if (raw.length >= 3 && !/^(?:CONST|LET|VAR|RETURN|VALUE|DATA|CONFIG)$/.test(raw)) {
      return raw;
    }
  }
  const defaults = {
    AWS_KEY: "AWS_ACCESS_KEY_ID",
    AWS_SECRET: "AWS_SECRET_ACCESS_KEY",
    OPENAI_KEY: "OPENAI_API_KEY",
    ANTHROPIC_KEY: "ANTHROPIC_API_KEY",
    GITHUB_TOKEN: "GITHUB_TOKEN",
    SLACK_TOKEN: "SLACK_BOT_TOKEN",
    STRIPE_KEY: "STRIPE_SECRET_KEY",
    PRIVATE_KEY: "PRIVATE_KEY_PEM",
    DB_URL: "DATABASE_URL",
    JWT: "AUTH_JWT_TOKEN",
    ENV_SECRET: "APP_SECRET_KEY",
  };
  return defaults[ruleId] || "SECRET_VALUE";
}

/**
 * Scan text for secrets and optionally PII.
 *
 * @param {string} text
 * @param {{
 *   includeSecrets?: boolean,
 *   includePii?: boolean,
 *   respectIgnoreComments?: boolean,
 *   filePath?: string,
 *   ignoreTestFiles?: boolean
 * }} [options]
 */
function scanText(text, options = {}) {
  const {
    includeSecrets = true,
    includePii = true,
    respectIgnoreComments = true,
    filePath = "",
    ignoreTestFiles = false,
  } = options;

  if (typeof text !== "string" || text.length === 0) {
    return [];
  }
  if (ignoreTestFiles && isLikelyTestOrFixturePath(filePath)) {
    return [];
  }

  const normalized = normalize1To1(text);
  const lineStarts = buildLineIndex(text);
  const candidates = [];

  for (const rule of RULES) {
    if (rule.kind === "secret" && !includeSecrets) {
      continue;
    }
    if (rule.kind === "pii" && !includePii) {
      continue;
    }

    const haystack = rule.useNormalized ? normalized : text;
    const re = new RegExp(rule.regex.source, rule.regex.flags);
    let match;

    while ((match = re.exec(haystack)) !== null) {
      let matchedValue = match[0];
      let start = match.index;
      let end = start + matchedValue.length;

      if (rule.captureGroup === "firstNonEmpty") {
        const g1 = match[1];
        const g2 = match[2];
        const captured = g1 !== undefined ? g1 : g2;
        if (!captured) {
          continue;
        }
        const sepIdx = match[0].search(/[:=]/);
        const searchFrom = sepIdx >= 0 ? sepIdx + 1 : 0;
        const localIdx = match[0].indexOf(captured, searchFrom);
        if (localIdx < 0) {
          continue;
        }
        start = match.index + localIdx;
        end = start + captured.length;
        matchedValue = text.slice(start, end);
      } else if (typeof rule.captureGroup === "number") {
        const captured = match[rule.captureGroup];
        if (!captured) {
          continue;
        }
        const sepIdx = match[0].search(/[:=]/);
        const searchFrom = sepIdx >= 0 ? sepIdx + 1 : 0;
        const localIdx = match[0].indexOf(captured, searchFrom);
        if (localIdx < 0) {
          continue;
        }
        start = match.index + localIdx;
        end = start + captured.length;
        matchedValue = text.slice(start, end);
      } else {
        matchedValue = text.slice(start, end);
      }

      if (rule.validate && !rule.validate(matchedValue, text, start, end)) {
        continue;
      }

      const startPos = offsetToPosition(lineStarts, start);
      if (respectIgnoreComments) {
        const lineStr = getLineText(text, lineStarts, startPos.line);
        if (hasIgnoreDirective(lineStr)) {
          continue;
        }
      }

      const endPos = offsetToPosition(lineStarts, end);
      candidates.push({
        ruleId: rule.id,
        tag: rule.tag,
        kind: rule.kind,
        severity: rule.severity,
        priority: rule.priority,
        description: rule.description,
        value: matchedValue,
        maskedPreview: maskSecretPreview(matchedValue),
        start,
        end,
        startLine: startPos.line,
        startCharacter: startPos.character,
        endLine: endPos.line,
        endCharacter: endPos.character,
      });
    }
  }

  // Deterministic overlap resolution: earlier start -> higher priority -> longer span
  candidates.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    if (a.priority !== b.priority) return a.priority - b.priority;
    return b.end - b.start - (a.end - a.start);
  });

  const accepted = [];
  let lastEnd = -1;
  for (const item of candidates) {
    if (item.start >= lastEnd) {
      accepted.push(item);
      lastEnd = item.end;
    }
  }

  return accepted;
}

/**
 * In-memory session-only reversible redaction vault.
 * Never persists sensitive values to disk.
 */
class RedactionVault {
  constructor() {
    this.valueToPlaceholder = new Map();
    this.placeholderToValue = new Map();
    this.counters = new Map();
  }

  getOrCreatePlaceholder(tag, originalValue) {
    if (this.valueToPlaceholder.has(originalValue)) {
      return this.valueToPlaceholder.get(originalValue);
    }
    const nextNum = (this.counters.get(tag) || 0) + 1;
    this.counters.set(tag, nextNum);
    const placeholder = `[[SECRET_${tag}_${nextNum}]]`;
    this.valueToPlaceholder.set(originalValue, placeholder);
    this.placeholderToValue.set(placeholder, originalValue);
    return placeholder;
  }

  /**
   * Redact secrets & PII in text using deterministic reversible placeholders.
   *
   * @param {string} text
   * @param {{ includeSecrets?: boolean, includePii?: boolean, respectIgnoreComments?: boolean }} [options]
   */
  redact(text, options = {}) {
    const findings = scanText(text, {
      includeSecrets: options.includeSecrets !== undefined ? options.includeSecrets : true,
      includePii: options.includePii !== undefined ? options.includePii : true,
      respectIgnoreComments:
        options.respectIgnoreComments !== undefined ? options.respectIgnoreComments : false,
      ignoreTestFiles: false,
    });

    if (findings.length === 0) {
      return {
        redactedText: text,
        findings: [],
        redactedCount: 0,
        uniqueCount: 0,
        byCategory: {},
      };
    }

    let cursor = 0;
    const chunks = [];
    const byCategory = {};
    const uniquePlaceholders = new Set();
    const enrichedFindings = [];

    for (const f of findings) {
      chunks.push(text.slice(cursor, f.start));
      const placeholder = this.getOrCreatePlaceholder(f.tag, f.value);
      chunks.push(placeholder);
      cursor = f.end;

      uniquePlaceholders.add(placeholder);
      byCategory[f.ruleId] = (byCategory[f.ruleId] || 0) + 1;
      enrichedFindings.push({ ...f, placeholder });
    }
    chunks.push(text.slice(cursor));

    return {
      redactedText: chunks.join(""),
      findings: enrichedFindings,
      redactedCount: findings.length,
      uniqueCount: uniquePlaceholders.size,
      byCategory,
    };
  }

  /**
   * Restore any known [[SECRET_<TAG>_<N>]] placeholders back to their original values.
   * Uses callback replacement so `$&` or `$1` inside passwords is never mangled.
   *
   * @param {string} text
   */
  restore(text) {
    if (typeof text !== "string" || text.length === 0) {
      return {
        restoredText: text || "",
        replacedCount: 0,
        unknownPlaceholders: [],
      };
    }

    let replacedCount = 0;
    const unknownSet = new Set();

    const restoredText = text.replace(/\[\[SECRET_[A-Z0-9_]+_\d+\]\]/g, (token) => {
      if (this.placeholderToValue.has(token)) {
        replacedCount += 1;
        return this.placeholderToValue.get(token);
      }
      unknownSet.add(token);
      return token;
    });

    return {
      restoredText,
      replacedCount,
      unknownPlaceholders: Array.from(unknownSet),
    };
  }

  size() {
    return this.placeholderToValue.size;
  }

  clear() {
    this.valueToPlaceholder.clear();
    this.placeholderToValue.clear();
    this.counters.clear();
  }
}

module.exports = {
  RULES,
  normalize1To1,
  isValidMyNumber,
  isSensitiveIpv4,
  isLikelyTestOrFixturePath,
  isLikelyPlaceholderOrEnvRef,
  hasIgnoreDirective,
  maskSecretPreview,
  suggestEnvVarName,
  scanText,
  RedactionVault,
};
