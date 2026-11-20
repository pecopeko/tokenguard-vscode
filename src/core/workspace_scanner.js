"use strict";

const fs = require("fs");
const path = require("path");
const { estimateTokens, calculateAllModelCosts, formatUsd } = require("./tokenizer");
const { scanText } = require("./redactor");

/**
 * `.gitignore`-aware workspace scanner for TokenGuard Pro:
 *   1. Workspace Context Budget & Multi-Model Cost Report
 *   2. Pre-Commit / Workspace Secret & PII Compliance Audit Report
 *
 * Pure CommonJS, zero runtime dependencies.
 */

const ALWAYS_IGNORED_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  ".venv",
  "venv",
  "__pycache__",
  ".mypy_cache",
  ".pytest_cache",
  ".next",
  ".nuxt",
]);

const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".ico",
  ".tif",
  ".tiff",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".tgz",
  ".bz2",
  ".7z",
  ".rar",
  ".vsix",
  ".wasm",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".bin",
  ".o",
  ".a",
  ".pyc",
  ".class",
  ".jar",
  ".woff",
  ".woff2",
  ".ttf",
  ".otf",
  ".eot",
  ".mp3",
  ".mp4",
  ".mov",
  ".avi",
  ".wav",
  ".flac",
  ".sqlite",
  ".sqlite3",
  ".db",
  ".parquet",
  ".arrow",
]);

function escapeRegexChar(ch) {
  return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Convert a single `.gitignore` glob pattern into a RegExp.
 *
 * @param {string} pattern
 * @param {boolean} anchored
 * @param {boolean} dirOnly
 */
function compileGitignorePattern(pattern, anchored, dirOnly) {
  let expr = "";
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        if (pattern[i + 2] === "/") {
          expr += "(?:.*/)?";
          i += 2;
        } else {
          expr += ".*";
          i += 1;
        }
      } else {
        expr += "[^/]*";
      }
    } else if (ch === "?") {
      expr += "[^/]";
    } else {
      expr += escapeRegexChar(ch);
    }
  }

  const prefix = anchored ? "^" : "(?:^|/)";
  const suffix = dirOnly ? "(?:/|$)" : "(?:/.*|$)";
  return new RegExp(`${prefix}${expr}${suffix}`);
}

/**
 * Parse `.gitignore` file contents into ordered ignore/unignore matcher rules.
 *
 * @param {string} content
 * @param {string} [baseRelDir]
 */
function parseGitignore(content, baseRelDir = "") {
  const rules = [];
  const lines = String(content || "").split(/\r?\n/);

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    let negated = false;
    let pattern = trimmed;
    if (pattern.startsWith("!")) {
      negated = true;
      pattern = pattern.slice(1);
    } else if (pattern.startsWith("\\#") || pattern.startsWith("\\!")) {
      pattern = pattern.slice(1);
    }

    if (!pattern) {
      continue;
    }

    let dirOnly = false;
    if (pattern.endsWith("/")) {
      dirOnly = true;
      pattern = pattern.slice(0, -1);
    }

    let anchored = false;
    if (pattern.startsWith("/")) {
      anchored = true;
      pattern = pattern.slice(1);
    } else if (pattern.includes("/")) {
      anchored = true;
    }

    if (!pattern) {
      continue;
    }

    const regex = compileGitignorePattern(pattern, anchored, dirOnly);
    rules.push({
      negated,
      dirOnly,
      baseRelDir: baseRelDir ? `${baseRelDir}/` : "",
      regex,
      raw: trimmed,
    });
  }

  return rules;
}

/**
 * Evaluate whether a workspace-relative POSIX path is ignored by accumulated gitignore rules.
 *
 * @param {string} relPosixPath
 * @param {boolean} isDir
 * @param {ReturnType<typeof parseGitignore>} rules
 * @returns {boolean}
 */
function isIgnoredByRules(relPosixPath, isDir, rules) {
  let ignored = false;
  for (const rule of rules) {
    let targetPath = relPosixPath;
    if (rule.baseRelDir) {
      if (!relPosixPath.startsWith(rule.baseRelDir)) {
        continue;
      }
      targetPath = relPosixPath.slice(rule.baseRelDir.length);
    }
    if (rule.dirOnly && !isDir && !targetPath.includes("/")) {
      continue;
    }
    if (rule.regex.test(targetPath)) {
      ignored = !rule.negated;
    }
  }
  return ignored;
}

function looksLikeBinaryBuffer(buf) {
  const probeLen = Math.min(buf.length, 4096);
  for (let i = 0; i < probeLen; i += 1) {
    if (buf[i] === 0) {
      return true;
    }
  }
  return false;
}

/**
 * Walk a workspace directory synchronously respecting `.gitignore` rules, skipping binaries & large blobs.
 *
 * @param {string} rootDir
 * @param {{ maxFiles?: number, maxFileBytes?: number, extraIgnoreRules?: string[] }} [options]
 */
function collectWorkspaceFiles(rootDir, options = {}) {
  const maxFiles = options.maxFiles !== undefined ? options.maxFiles : 2000;
  const maxFileBytes = options.maxFileBytes !== undefined ? options.maxFileBytes : 512 * 1024;
  const resolvedRoot = path.resolve(rootDir);

  const initialRules = [];
  if (Array.isArray(options.extraIgnoreRules) && options.extraIgnoreRules.length > 0) {
    initialRules.push(...parseGitignore(options.extraIgnoreRules.join("\n"), ""));
  }

  const files = [];
  const stats = {
    ignoredCount: 0,
    skippedBinaryCount: 0,
    skippedLargeCount: 0,
    skippedUnreadableCount: 0,
    truncated: false,
  };

  function walk(absDir, relPosixDir, inheritedRules) {
    if (files.length >= maxFiles) {
      stats.truncated = true;
      return;
    }

    let rules = inheritedRules;
    const gitignorePath = path.join(absDir, ".gitignore");
    try {
      if (fs.existsSync(gitignorePath) && fs.statSync(gitignorePath).isFile()) {
        const parsed = parseGitignore(fs.readFileSync(gitignorePath, "utf8"), relPosixDir);
        if (parsed.length > 0) {
          rules = [...inheritedRules, ...parsed];
        }
      }
    } catch (_) {
      // Unreadable .gitignore does not abort scan
    }

    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch (_) {
      stats.skippedUnreadableCount += 1;
      return;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (files.length >= maxFiles) {
        stats.truncated = true;
        return;
      }
      if (entry.isSymbolicLink()) {
        continue;
      }

      const relPosix = relPosixDir ? `${relPosixDir}/${entry.name}` : entry.name;
      const absPath = path.join(absDir, entry.name);

      if (entry.isDirectory()) {
        if (ALWAYS_IGNORED_DIRS.has(entry.name) || isIgnoredByRules(relPosix, true, rules)) {
          stats.ignoredCount += 1;
          continue;
        }
        walk(absPath, relPosix, rules);
      } else if (entry.isFile()) {
        if (entry.name === ".DS_Store" || isIgnoredByRules(relPosix, false, rules)) {
          stats.ignoredCount += 1;
          continue;
        }
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXTENSIONS.has(ext)) {
          stats.skippedBinaryCount += 1;
          continue;
        }

        let stat;
        try {
          stat = fs.statSync(absPath);
        } catch (_) {
          stats.skippedUnreadableCount += 1;
          continue;
        }

        if (stat.size > maxFileBytes) {
          stats.skippedLargeCount += 1;
          continue;
        }

        let buf;
        try {
          buf = fs.readFileSync(absPath);
        } catch (_) {
          stats.skippedUnreadableCount += 1;
          continue;
        }

        if (looksLikeBinaryBuffer(buf)) {
          stats.skippedBinaryCount += 1;
          continue;
        }

        files.push({
          absPath,
          relPath: relPosix,
          ext: ext || "(no ext)",
          bytes: buf.length,
          content: buf.toString("utf8"),
        });
      }
    }
  }

  walk(resolvedRoot, "", initialRules);
  return { rootDir: resolvedRoot, files, stats };
}

/**
 * Pro Feature 1: Compute full-workspace Context Budget & Multi-Model Cost Report.
 *
 * @param {string} rootDir
 * @param {{ maxFiles?: number, maxFileBytes?: number, topN?: number }} [options]
 */
function scanWorkspaceContextBudget(rootDir, options = {}) {
  const topN = options.topN !== undefined ? options.topN : 25;
  const { files, stats } = collectWorkspaceFiles(rootDir, options);

  const fileReports = [];
  const byExtensionMap = new Map();
  let totalTokens = 0;
  let totalChars = 0;
  let totalLines = 0;
  let totalBytes = 0;

  for (const file of files) {
    const est = estimateTokens(file.content);
    totalTokens += est.tokens;
    totalChars += est.characters;
    totalLines += est.lines;
    totalBytes += file.bytes;

    fileReports.push({
      relPath: file.relPath,
      ext: file.ext,
      tokens: est.tokens,
      characters: est.characters,
      lines: est.lines,
      bytes: file.bytes,
      dominantScript: est.dominantScript,
    });

    const cur = byExtensionMap.get(file.ext) || { ext: file.ext, files: 0, tokens: 0, bytes: 0 };
    cur.files += 1;
    cur.tokens += est.tokens;
    cur.bytes += file.bytes;
    byExtensionMap.set(file.ext, cur);
  }

  fileReports.sort((a, b) => b.tokens - a.tokens || a.relPath.localeCompare(b.relPath));

  const byExtension = Array.from(byExtensionMap.values()).sort((a, b) => b.tokens - a.tokens);
  const modelCosts = calculateAllModelCosts(totalTokens);

  return {
    workspaceName: path.basename(path.resolve(rootDir)),
    rootDir: path.resolve(rootDir),
    generatedAt: new Date().toISOString(),
    totals: {
      filesScanned: files.length,
      tokens: totalTokens,
      characters: totalChars,
      lines: totalLines,
      bytes: totalBytes,
      ...stats,
    },
    topFiles: fileReports.slice(0, topN),
    allFiles: fileReports,
    byExtension,
    modelCosts,
  };
}

/**
 * Pro Feature 2: Scan entire workspace for hardcoded secrets & PII compliance leaks.
 *
 * @param {string} rootDir
 * @param {{
 *   maxFiles?: number,
 *   maxFileBytes?: number,
 *   includePii?: boolean,
 *   ignoreTestFiles?: boolean
 * }} [options]
 */
function scanWorkspaceSecrets(rootDir, options = {}) {
  const includePii = options.includePii !== undefined ? options.includePii : true;
  const ignoreTestFiles = options.ignoreTestFiles !== undefined ? options.ignoreTestFiles : false;
  const { files, stats } = collectWorkspaceFiles(rootDir, options);

  const findings = [];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const categoryCounts = {};
  const affectedFiles = new Set();

  for (const file of files) {
    const fileFindings = scanText(file.content, {
      includeSecrets: true,
      includePii,
      respectIgnoreComments: true,
      filePath: file.relPath,
      ignoreTestFiles,
    });

    for (const f of fileFindings) {
      affectedFiles.add(file.relPath);
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
      categoryCounts[f.ruleId] = (categoryCounts[f.ruleId] || 0) + 1;
      findings.push({
        file: file.relPath,
        line: f.startLine + 1,
        column: f.startCharacter + 1,
        ruleId: f.ruleId,
        kind: f.kind,
        severity: f.severity,
        description: f.description,
        maskedPreview: f.maskedPreview,
      });
    }
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => {
    const sDiff = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    if (sDiff !== 0) return sDiff;
    const fDiff = a.file.localeCompare(b.file);
    if (fDiff !== 0) return fDiff;
    return a.line - b.line;
  });

  return {
    workspaceName: path.basename(path.resolve(rootDir)),
    rootDir: path.resolve(rootDir),
    generatedAt: new Date().toISOString(),
    options: { includePii, ignoreTestFiles },
    summary: {
      filesScanned: files.length,
      affectedFilesCount: affectedFiles.size,
      totalFindings: findings.length,
      severityCounts,
      categoryCounts,
      status: findings.length === 0 ? "PASS" : severityCounts.critical > 0 ? "FAIL_CRITICAL" : "WARN",
      ...stats,
    },
    findings,
  };
}

/**
 * Render clean Markdown compliance audit report (never exposes raw secret values).
 *
 * @param {ReturnType<typeof scanWorkspaceSecrets>} report
 * @returns {string}
 */
function formatAuditMarkdown(report) {
  const { summary, findings } = report;
  const lines = [
    `# TokenGuard Pro — Secret & PII Compliance Audit Report`,
    ``,
    `- **Workspace**: \`${report.workspaceName}\``,
    `- **Generated**: \`${report.generatedAt}\``,
    `- **Status**: **${summary.status}**`,
    `- **Files Scanned**: ${summary.filesScanned} (ignored: ${summary.ignoredCount}, binary skipped: ${summary.skippedBinaryCount}, large skipped: ${summary.skippedLargeCount})`,
    `- **Total Findings**: ${summary.totalFindings} across ${summary.affectedFilesCount} file(s)`,
    `- **Severity Breakdown**: Critical: ${summary.severityCounts.critical} | High: ${summary.severityCounts.high} | Medium: ${summary.severityCounts.medium} | Low: ${summary.severityCounts.low}`,
    ``,
  ];

  if (findings.length === 0) {
    lines.push(`> No hardcoded secrets or PII leaks detected across ${summary.filesScanned} scanned files.`);
    return lines.join("\n");
  }

  lines.push(`## Findings (Masked Previews Only)`);
  lines.push(``);
  lines.push(`| Severity | Category | Kind | Location | Masked Preview |`);
  lines.push(`| --- | --- | --- | --- | --- |`);
  for (const f of findings) {
    const safeFile = f.file.replace(/\|/g, "\\|");
    const safePreview = f.maskedPreview.replace(/\|/g, "\\|");
    lines.push(
      `| **${f.severity.toUpperCase()}** | \`${f.ruleId}\` | ${f.kind} | \`${safeFile}:${f.line}:${f.column}\` | \`${safePreview}\` |`
    );
  }
  lines.push(``);
  lines.push(`---`);
  lines.push(`*Generated 100% locally by TokenGuard Pro. Zero data left your machine.*`);
  return lines.join("\n");
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Render interactive HTML Webview for Pro Workspace Context Budget & Cost Report.
 *
 * @param {ReturnType<typeof scanWorkspaceContextBudget>} report
 * @param {string} licenseSummary
 * @returns {string}
 */
function renderBudgetWebviewHtml(report, licenseSummary) {
  const maxFileTokens = report.topFiles.length > 0 ? Math.max(1, report.topFiles[0].tokens) : 1;

  const modelRows = report.modelCosts
    .map((m) => {
      const pct = Math.min(100, m.contextPercent).toFixed(1);
      const badge = m.fitsContext
        ? `<span class="badge ok">Fits (${pct}%)</span>`
        : `<span class="badge warn">Exceeds (${m.contextPercent.toFixed(0)}%)</span>`;
      return `<tr>
        <td><strong>${escapeHtml(m.modelName)}</strong> <span class="muted">${escapeHtml(m.provider)}</span></td>
        <td class="num">$${m.inputPerMillionUsd.toFixed(2)} / 1M</td>
        <td class="num"><strong>${escapeHtml(formatUsd(m.inputCostUsd))}</strong></td>
        <td class="num">${(m.contextWindow / 1000).toLocaleString("en-US")}K</td>
        <td>${badge}</td>
      </tr>`;
    })
    .join("\n");

  const fileRows = report.topFiles
    .map((f, idx) => {
      const share = report.totals.tokens > 0 ? ((f.tokens / report.totals.tokens) * 100).toFixed(1) : "0.0";
      const barWidth = Math.max(3, Math.round((f.tokens / maxFileTokens) * 100));
      return `<tr>
        <td class="num muted">${idx + 1}</td>
        <td><code>${escapeHtml(f.relPath)}</code></td>
        <td class="num">${f.tokens.toLocaleString("en-US")}</td>
        <td class="num">${share}%</td>
        <td style="width:140px"><div class="bar-track"><div class="bar-fill" style="width:${barWidth}%"></div></div></td>
        <td class="muted">${escapeHtml(f.dominantScript)}</td>
      </tr>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>TokenGuard Pro — Workspace Context Budget</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 20px 24px; color: var(--vscode-editor-foreground, #e2e8f0); background: var(--vscode-editor-background, #0f172a); line-height: 1.5; }
  h1 { margin: 0 0 4px; font-size: 20px; display: flex; align-items: center; gap: 10px; }
  h2 { margin: 24px 0 10px; font-size: 15px; border-bottom: 1px solid rgba(148,163,184,0.2); padding-bottom: 6px; }
  .pill { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: rgba(16,185,129,0.18); color: #34d399; font-weight: 600; }
  .muted { color: var(--vscode-descriptionForeground, #94a3b8); font-size: 12px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin: 16px 0; }
  .card { background: rgba(148,163,184,0.08); border: 1px solid rgba(148,163,184,0.18); border-radius: 8px; padding: 12px 14px; }
  .card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--vscode-descriptionForeground, #94a3b8); }
  .card .value { font-size: 22px; font-weight: 700; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(148,163,184,0.14); }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--vscode-descriptionForeground, #94a3b8); }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600; }
  .badge.ok { background: rgba(16,185,129,0.18); color: #34d399; }
  .badge.warn { background: rgba(245,158,11,0.2); color: #fbbf24; }
  .bar-track { width: 100%; height: 8px; background: rgba(148,163,184,0.15); border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: linear-gradient(90deg, #38bdf8, #10b981); border-radius: 4px; }
</style>
</head>
<body>
  <h1>TokenGuard Pro — Workspace Context Budget <span class="pill">100% LOCAL</span></h1>
  <div class="muted">Workspace: <strong>${escapeHtml(report.workspaceName)}</strong> · License: ${escapeHtml(licenseSummary)} · Generated: ${escapeHtml(report.generatedAt)}</div>

  <div class="grid">
    <div class="card"><div class="label">Total Tokens</div><div class="value">${report.totals.tokens.toLocaleString("en-US")}</div></div>
    <div class="card"><div class="label">Files Scanned</div><div class="value">${report.totals.filesScanned.toLocaleString("en-US")}</div></div>
    <div class="card"><div class="label">Total Lines</div><div class="value">${report.totals.lines.toLocaleString("en-US")}</div></div>
    <div class="card"><div class="label">Ignored / Skipped</div><div class="value">${(report.totals.ignoredCount + report.totals.skippedBinaryCount + report.totals.skippedLargeCount).toLocaleString("en-US")}</div></div>
  </div>

  <h2>Full-Repo Context Cost Across 6 Frontier Models (1x Full Input Pass)</h2>
  <table>
    <thead><tr><th>Model</th><th class="num">Input Rate</th><th class="num">Est. Input Cost</th><th class="num">Context</th><th>Fit</th></tr></thead>
    <tbody>${modelRows}</tbody>
  </table>

  <h2>Top ${report.topFiles.length} Token-Heavy Files (.gitignore respected)</h2>
  <table>
    <thead><tr><th class="num">#</th><th>File</th><th class="num">Tokens</th><th class="num">Share</th><th>Weight</th><th>Script</th></tr></thead>
    <tbody>${fileRows || '<tr><td colspan="6" class="muted">No eligible text files found.</td></tr>'}</tbody>
  </table>
</body>
</html>`;
}

/**
 * Render interactive HTML Webview for Pro Secret & PII Compliance Audit Report.
 *
 * @param {ReturnType<typeof scanWorkspaceSecrets>} report
 * @param {string} licenseSummary
 * @returns {string}
 */
function renderAuditWebviewHtml(report, licenseSummary) {
  const rows = report.findings
    .map(
      (f) => `<tr>
      <td><span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span></td>
      <td><code>${escapeHtml(f.ruleId)}</code></td>
      <td>${escapeHtml(f.kind)}</td>
      <td><code>${escapeHtml(f.file)}:${f.line}:${f.column}</code></td>
      <td><code>${escapeHtml(f.maskedPreview)}</code></td>
    </tr>`
    )
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>TokenGuard Pro — Secret & PII Audit Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 20px 24px; color: var(--vscode-editor-foreground, #e2e8f0); background: var(--vscode-editor-background, #0f172a); line-height: 1.5; }
  h1 { margin: 0 0 4px; font-size: 20px; display: flex; align-items: center; gap: 10px; }
  h2 { margin: 22px 0 10px; font-size: 15px; border-bottom: 1px solid rgba(148,163,184,0.2); padding-bottom: 6px; }
  .muted { color: var(--vscode-descriptionForeground, #94a3b8); font-size: 12px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 16px 0; }
  .card { background: rgba(148,163,184,0.08); border: 1px solid rgba(148,163,184,0.18); border-radius: 8px; padding: 12px 14px; }
  .card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--vscode-descriptionForeground, #94a3b8); }
  .card .value { font-size: 22px; font-weight: 700; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid rgba(148,163,184,0.14); }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--vscode-descriptionForeground, #94a3b8); }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .sev { font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 700; }
  .sev.critical { background: rgba(239,68,68,0.22); color: #f87171; }
  .sev.high { background: rgba(249,115,22,0.22); color: #fb923c; }
  .sev.medium { background: rgba(234,179,8,0.22); color: #facc15; }
  .sev.low { background: rgba(56,189,248,0.2); color: #38bdf8; }
  .clean { padding: 16px; border-radius: 8px; background: rgba(16,185,129,0.14); color: #34d399; font-weight: 600; }
</style>
</head>
<body>
  <h1>TokenGuard Pro — Pre-Commit Secret &amp; PII Audit</h1>
  <div class="muted">Workspace: <strong>${escapeHtml(report.workspaceName)}</strong> · License: ${escapeHtml(licenseSummary)} · Status: <strong>${escapeHtml(report.summary.status)}</strong></div>

  <div class="grid">
    <div class="card"><div class="label">Files Scanned</div><div class="value">${report.summary.filesScanned}</div></div>
    <div class="card"><div class="label">Total Findings</div><div class="value">${report.summary.totalFindings}</div></div>
    <div class="card"><div class="label">Critical</div><div class="value">${report.summary.severityCounts.critical}</div></div>
    <div class="card"><div class="label">High / Med</div><div class="value">${report.summary.severityCounts.high + report.summary.severityCounts.medium}</div></div>
  </div>

  <h2>Audit Findings (Masked Previews Only)</h2>
  ${
    report.findings.length === 0
      ? `<div class="clean">PASS — Zero hardcoded secrets or PII leaks detected across ${report.summary.filesScanned} scanned files.</div>`
      : `<table>
          <thead><tr><th>Severity</th><th>Rule</th><th>Kind</th><th>Location</th><th>Masked Preview</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`
  }
</body>
</html>`;
}

module.exports = {
  parseGitignore,
  isIgnoredByRules,
  collectWorkspaceFiles,
  scanWorkspaceContextBudget,
  scanWorkspaceSecrets,
  formatAuditMarkdown,
  renderBudgetWebviewHtml,
  renderAuditWebviewHtml,
};
