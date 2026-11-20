"use strict";

const {
  estimateTokens,
  calculateModelCost,
  calculateAllModelCosts,
  formatUsd,
  formatStatusBarLabel,
} = require("./src/core/tokenizer");
const {
  RedactionVault,
  scanText,
  suggestEnvVarName,
} = require("./src/core/redactor");
const {
  compressJsonToSchema,
  expandSchemaToJson,
} = require("./src/core/compressor");
const {
  verifyLicenseKey,
  formatLicenseSummary,
} = require("./src/core/license");
const {
  scanWorkspaceContextBudget,
  scanWorkspaceSecrets,
  formatAuditMarkdown,
  renderBudgetWebviewHtml,
  renderAuditWebviewHtml,
} = require("./src/core/workspace_scanner");

const LICENSE_STORAGE_KEY = "tokenguard.proLicenseKey";

function getEnvReplacement(languageId, varName) {
  switch (languageId) {
    case "python":
      return `os.environ["${varName}"]`;
    case "go":
      return `os.Getenv("${varName}")`;
    case "ruby":
      return `ENV.fetch("${varName}")`;
    case "rust":
      return `std::env::var("${varName}")?`;
    case "php":
      return `getenv('${varName}')`;
    case "shellscript":
    case "dotenv":
    case "yaml":
    case "dockerfile":
      return `\${${varName}}`;
    default:
      return `process.env.${varName}`;
  }
}

function getLineCommentPrefix(languageId) {
  switch (languageId) {
    case "python":
    case "ruby":
    case "shellscript":
    case "yaml":
    case "toml":
    case "dotenv":
    case "dockerfile":
    case "makefile":
      return "#";
    case "sql":
    case "lua":
    case "haskell":
      return "--";
    default:
      return "//";
  }
}

/**
 * Factory accepting the VS Code API module so both the real Extension Host
 * and offline unit tests exercise the exact same activation & command logic.
 *
 * @param {any} vscode
 * @param {{ publicKeyPem?: string, now?: () => Date }} [testHooks]
 */
function createExtension(vscode, testHooks = {}) {
  function activate(context) {
    const vault = new RedactionVault();
    const diagnostics = vscode.languages.createDiagnosticCollection("tokenguard");
    const statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    statusBarItem.command = "tokenguard.showTokenBreakdown";

    let debounceTimer = null;
    let cachedLicenseState = { valid: false, tier: "free", reason: "empty_key", payload: null };

    function getConfig() {
      return vscode.workspace.getConfiguration("tokenguard");
    }

    async function readStoredLicenseKey() {
      if (context.secrets && typeof context.secrets.get === "function") {
        const val = await context.secrets.get(LICENSE_STORAGE_KEY);
        if (val) return val;
      }
      if (context.globalState && typeof context.globalState.get === "function") {
        return context.globalState.get(LICENSE_STORAGE_KEY) || "";
      }
      return "";
    }

    async function storeLicenseKey(key) {
      if (context.secrets && typeof context.secrets.store === "function") {
        if (key) {
          await context.secrets.store(LICENSE_STORAGE_KEY, key);
        } else if (typeof context.secrets.delete === "function") {
          await context.secrets.delete(LICENSE_STORAGE_KEY);
        }
      }
      if (context.globalState && typeof context.globalState.update === "function") {
        await context.globalState.update(LICENSE_STORAGE_KEY, key || undefined);
      }
    }

    async function refreshLicenseState() {
      const rawKey = await readStoredLicenseKey();
      cachedLicenseState = verifyLicenseKey(rawKey, {
        publicKeyPem: testHooks.publicKeyPem,
        now: testHooks.now ? testHooks.now() : undefined,
      });
      return cachedLicenseState;
    }

    function buildTooltip(est, isSelection, secretCount) {
      const flagships = ["gpt-5", "claude-sonnet-4", "gemini-2.5-pro"].map((id) =>
        calculateModelCost(est.tokens, id)
      );
      const scopeLabel = isSelection ? "Current Selection" : "Active File";
      const lines = [
        `**TokenGuard — ${scopeLabel}**`,
        ``,
        `Tokens: **${est.tokens.toLocaleString("en-US")}** · Chars: ${est.characters.toLocaleString("en-US")} · Lines: ${est.lines.toLocaleString("en-US")} · Script: \`${est.dominantScript}\``,
        ``,
        ...flagships.map(
          (m) =>
            `- **${m.modelName}**: ${formatUsd(m.inputCostUsd)} input (${m.contextPercent.toFixed(2)}% of ${(m.contextWindow / 1000).toFixed(0)}K ctx)`
        ),
        ``,
        `Secret Diagnostics: **${secretCount}** · Session Vault: **${vault.size()}** redacted · Tier: **${formatLicenseSummary(cachedLicenseState)}**`,
        ``,
        `_Click to view all 6 models & switch status bar model._`,
      ];
      if (typeof vscode.MarkdownString === "function") {
        const md = new vscode.MarkdownString(lines.join("\n"));
        md.isTrusted = false;
        return md;
      }
      return lines.join("\n");
    }

    function updateDiagnosticsForDocument(document) {
      if (!document || typeof document.getText !== "function") {
        return 0;
      }
      const config = getConfig();
      const enabled = config.get("enableLiveDiagnostics", true);
      if (!enabled) {
        diagnostics.delete(document.uri);
        return 0;
      }

      const ignoreTestFiles = config.get("diagnostics.ignoreTestFiles", true);
      const includePii = config.get("diagnostics.includePii", false);
      const filePath = document.uri && document.uri.fsPath ? document.uri.fsPath : document.fileName || "";
      const text = document.getText();

      const findings = scanText(text, {
        includeSecrets: true,
        includePii,
        respectIgnoreComments: true,
        filePath,
        ignoreTestFiles,
      });

      const vsDiagnostics = findings.map((f) => {
        const range = new vscode.Range(
          new vscode.Position(f.startLine, f.startCharacter),
          new vscode.Position(f.endLine, f.endCharacter)
        );
        const severity =
          f.severity === "critical"
            ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;
        const diag = new vscode.Diagnostic(
          range,
          `TokenGuard: Potential ${f.description} detected (${f.maskedPreview}). Replace with env var or copy safely.`,
          severity
        );
        diag.source = "TokenGuard";
        diag.code = f.ruleId;
        return diag;
      });

      diagnostics.set(document.uri, vsDiagnostics);
      return vsDiagnostics.length;
    }

    function updateStatusBarNow(editor) {
      const activeEditor = editor !== undefined ? editor : vscode.window.activeTextEditor;
      if (!activeEditor || !activeEditor.document) {
        statusBarItem.hide();
        return null;
      }

      const doc = activeEditor.document;
      const selection = activeEditor.selection;
      const hasSelection = selection && !selection.isEmpty;
      const targetText = hasSelection ? doc.getText(selection) : doc.getText();

      const config = getConfig();
      const modelId = config.get("defaultModel", "claude-sonnet-4");
      const est = estimateTokens(targetText);
      const secretCount = updateDiagnosticsForDocument(doc);

      statusBarItem.text = formatStatusBarLabel({
        tokens: est.tokens,
        isSelection: Boolean(hasSelection),
        modelId,
        secretCount,
      });
      statusBarItem.tooltip = buildTooltip(est, Boolean(hasSelection), secretCount);
      statusBarItem.show();
      return { est, secretCount, isSelection: Boolean(hasSelection), modelId };
    }

    function scheduleUpdate(editor) {
      const config = getConfig();
      const debounceMs = Math.max(20, Math.min(2000, Number(config.get("statusBar.debounceMs", 200)) || 200));
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(() => {
        debounceTimer = null;
        updateStatusBarNow(editor);
      }, debounceMs);
    }

    async function ensureProLicense(featureName) {
      const status = await refreshLicenseState();
      if (status.valid) {
        return status;
      }

      const message =
        status.reason === "expired"
          ? `Your TokenGuard Pro license expired (${status.payload.expiresAt.slice(0, 10)}). Renew or enter a new Pro key to run "${featureName}".`
          : `"${featureName}" is a TokenGuard Pro feature ($9/mo or $29 lifetime — 100% offline cryptographic license key).`;

      const choice = await vscode.window.showInformationMessage(
        message,
        "Enter License Key",
        "Get TokenGuard Pro"
      );

      if (choice === "Enter License Key") {
        await handleEnterLicenseKey();
        const rechecked = await refreshLicenseState();
        return rechecked.valid ? rechecked : null;
      }
      if (choice === "Get TokenGuard Pro") {
        const checkoutUrl = getConfig().get(
          "proCheckoutUrl",
          "https://github.com/pecopeko/tokenguard-vscode#tokenguard-pro"
        );
        if (vscode.env && typeof vscode.env.openExternal === "function" && vscode.Uri) {
          await vscode.env.openExternal(vscode.Uri.parse(checkoutUrl));
        }
      }
      return null;
    }

    async function handleCopySafely() {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("TokenGuard: Open a file or select code to copy safely.");
        return null;
      }
      const doc = editor.document;
      const sel = editor.selection;
      const sourceText = sel && !sel.isEmpty ? doc.getText(sel) : doc.getText();
      if (!sourceText) {
        vscode.window.showInformationMessage("TokenGuard: Nothing to copy.");
        return null;
      }

      const result = vault.redact(sourceText, { includeSecrets: true, includePii: true });
      await vscode.env.clipboard.writeText(result.redactedText);

      if (result.redactedCount === 0) {
        vscode.window.showInformationMessage(
          "TokenGuard: Copied to clipboard — no secrets or PII detected."
        );
      } else {
        const cats = Object.entries(result.byCategory)
          .map(([k, v]) => `${k}: ${v}`)
          .join(", ");
        vscode.window.showInformationMessage(
          `TokenGuard: Copied safely — redacted ${result.redactedCount} item(s) (${cats}). Use "Restore Redacted Tokens" on AI replies.`
        );
      }
      updateStatusBarNow(editor);
      return result;
    }

    async function handleRestoreFromClipboard() {
      const editor = vscode.window.activeTextEditor;
      const hasEditorSelection = editor && editor.selection && !editor.selection.isEmpty;

      if (hasEditorSelection) {
        const selected = editor.document.getText(editor.selection);
        const restored = vault.restore(selected);
        if (restored.replacedCount > 0) {
          await editor.edit((editBuilder) => {
            editBuilder.replace(editor.selection, restored.restoredText);
          });
          vscode.window.showInformationMessage(
            `TokenGuard: Restored ${restored.replacedCount} redacted token(s) in editor selection.`
          );
          return restored;
        }
      }

      const clipText = await vscode.env.clipboard.readText();
      if (!clipText) {
        vscode.window.showInformationMessage("TokenGuard: Clipboard is empty.");
        return null;
      }

      const restored = vault.restore(clipText);
      if (restored.replacedCount === 0) {
        const hint =
          restored.unknownPlaceholders.length > 0
            ? ` Found ${restored.unknownPlaceholders.length} unknown placeholder(s) not in this session's vault.`
            : " No [[SECRET_...]] placeholders found.";
        vscode.window.showInformationMessage(`TokenGuard: Nothing restored.${hint}`);
        return restored;
      }

      if (editor) {
        await editor.edit((editBuilder) => {
          editBuilder.replace(editor.selection, restored.restoredText);
        });
        vscode.window.showInformationMessage(
          `TokenGuard: Pasted AI reply with ${restored.replacedCount} real secret/PII value(s) restored.`
        );
      } else {
        await vscode.env.clipboard.writeText(restored.restoredText);
        vscode.window.showInformationMessage(
          `TokenGuard: Restored ${restored.replacedCount} token(s) directly into clipboard.`
        );
      }
      return restored;
    }

    async function handleCompressJson() {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("TokenGuard: Select JSON or open a JSON file to compress.");
        return null;
      }
      const doc = editor.document;
      const sel = editor.selection;
      const hasSelection = sel && !sel.isEmpty;
      const rawText = hasSelection ? doc.getText(sel) : doc.getText();

      let result;
      try {
        result = compressJsonToSchema(rawText);
      } catch (err) {
        vscode.window.showErrorMessage(`TokenGuard: ${err.message}`);
        return null;
      }

      const targetRange = hasSelection
        ? sel
        : new vscode.Range(
            new vscode.Position(0, 0),
            doc.positionAt ? doc.positionAt(rawText.length) : new vscode.Position(doc.lineCount || 0, 0)
          );

      await editor.edit((editBuilder) => {
        editBuilder.replace(targetRange, result.compressed);
      });

      vscode.window.showInformationMessage(
        `TokenGuard: Compressed JSON → @schema (${result.originalTokens.toLocaleString("en-US")} → ${result.compressedTokens.toLocaleString("en-US")} tok, -${result.savedPercent}% · 100% lossless).`
      );
      updateStatusBarNow(editor);
      return result;
    }

    async function handleExpandSchema() {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("TokenGuard: Select a @schema block to expand back to JSON.");
        return null;
      }
      const doc = editor.document;
      const sel = editor.selection;
      const hasSelection = sel && !sel.isEmpty;
      const rawText = hasSelection ? doc.getText(sel) : doc.getText();

      let result;
      try {
        result = expandSchemaToJson(rawText, { indent: 2 });
      } catch (err) {
        vscode.window.showErrorMessage(`TokenGuard: ${err.message}`);
        return null;
      }

      const targetRange = hasSelection
        ? sel
        : new vscode.Range(
            new vscode.Position(0, 0),
            doc.positionAt ? doc.positionAt(rawText.length) : new vscode.Position(doc.lineCount || 0, 0)
          );

      await editor.edit((editBuilder) => {
        editBuilder.replace(targetRange, result.json);
      });

      vscode.window.showInformationMessage(
        `TokenGuard: Expanded @schema back to lossless JSON (${result.mode}).`
      );
      updateStatusBarNow(editor);
      return result;
    }

    async function handleShowTokenBreakdown() {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("TokenGuard: Open a file to inspect token & cost breakdown.");
        return null;
      }
      const doc = editor.document;
      const sel = editor.selection;
      const hasSelection = sel && !sel.isEmpty;
      const text = hasSelection ? doc.getText(sel) : doc.getText();
      const est = estimateTokens(text);
      const costs = calculateAllModelCosts(est.tokens);

      const items = costs.map((m) => ({
        label: `${m.modelName} (${m.provider})`,
        description: `${formatUsd(m.inputCostUsd)} input · ${formatUsd(m.outputCostUsd)} 1:1 output`,
        detail: `${est.tokens.toLocaleString("en-US")} tokens · ${m.contextPercent.toFixed(2)}% of ${(m.contextWindow / 1000).toFixed(0)}K context ($${m.inputPerMillionUsd}/1M in)`,
        modelId: m.modelId,
      }));

      const picked = await vscode.window.showQuickPick(items, {
        placeHolder: `${hasSelection ? "Selection" : "Active File"}: ${est.tokens.toLocaleString("en-US")} tokens (${est.dominantScript}) — select a model to pin to status bar`,
      });

      if (picked && picked.modelId) {
        const config = getConfig();
        if (typeof config.update === "function") {
          await config.update("defaultModel", picked.modelId, true);
        }
        updateStatusBarNow(editor);
      }
      return { est, costs, picked };
    }

    async function handleClearVault() {
      const count = vault.size();
      vault.clear();
      vscode.window.showInformationMessage(
        `TokenGuard: Cleared ${count} item(s) from session redaction vault.`
      );
      updateStatusBarNow();
      return count;
    }

    async function handleEnterLicenseKey() {
      const current = await refreshLicenseState();
      const entered = await vscode.window.showInputBox({
        title: "TokenGuard Pro — Offline License Key",
        prompt: current.valid
          ? `Active: ${formatLicenseSummary(current)}. Paste a new TGPRO-... key or leave blank to deactivate.`
          : "Paste your TokenGuard Pro license key (starts with TGPRO-). Verified 100% offline via Ed25519.",
        placeHolder: "TGPRO-<payload>.<signature>",
        ignoreFocusOut: true,
      });

      if (entered === undefined) {
        return current;
      }

      const trimmed = entered.trim();
      if (trimmed === "") {
        await storeLicenseKey("");
        const cleared = await refreshLicenseState();
        vscode.window.showInformationMessage("TokenGuard: License key cleared (switched to Free Tier).");
        updateStatusBarNow();
        return cleared;
      }

      const verification = verifyLicenseKey(trimmed, {
        publicKeyPem: testHooks.publicKeyPem,
        now: testHooks.now ? testHooks.now() : undefined,
      });

      if (!verification.valid) {
        vscode.window.showErrorMessage(
          `TokenGuard Pro: Invalid license key (${verification.reason}). Please verify the full TGPRO-... string.`
        );
        return verification;
      }

      await storeLicenseKey(trimmed);
      cachedLicenseState = verification;
      vscode.window.showInformationMessage(
        `TokenGuard Pro activated! ${formatLicenseSummary(verification)}`
      );
      updateStatusBarNow();
      return verification;
    }

    async function handleProWorkspaceBudget() {
      const license = await ensureProLicense("Workspace Context Budget & Cost Report");
      if (!license) {
        return { gated: true };
      }

      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage("TokenGuard Pro: Open a workspace folder first.");
        return null;
      }

      const rootDir = folders[0].uri.fsPath;
      const report = scanWorkspaceContextBudget(rootDir);
      const panel = vscode.window.createWebviewPanel(
        "tokenguard.workspaceBudget",
        `TokenGuard Pro: Context Budget (${report.workspaceName})`,
        vscode.ViewColumn.One,
        { enableScripts: false }
      );
      panel.webview.html = renderBudgetWebviewHtml(report, formatLicenseSummary(license));
      return { gated: false, report, panel };
    }

    async function handleProWorkspaceAudit() {
      const license = await ensureProLicense("Pre-Commit / Workspace Secret & PII Audit Report");
      if (!license) {
        return { gated: true };
      }

      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage("TokenGuard Pro: Open a workspace folder first.");
        return null;
      }

      const rootDir = folders[0].uri.fsPath;
      const report = scanWorkspaceSecrets(rootDir, { includePii: true, ignoreTestFiles: false });
      const panel = vscode.window.createWebviewPanel(
        "tokenguard.workspaceAudit",
        `TokenGuard Pro: Secret Audit (${report.workspaceName})`,
        vscode.ViewColumn.One,
        { enableScripts: false }
      );
      panel.webview.html = renderAuditWebviewHtml(report, formatLicenseSummary(license));

      const markdown = formatAuditMarkdown(report);
      const exportChoice = await vscode.window.showInformationMessage(
        `TokenGuard Pro Audit: ${report.summary.status} — ${report.summary.totalFindings} finding(s) across ${report.summary.filesScanned} file(s).`,
        "Open Markdown Report",
        "Open JSON Report"
      );

      if (exportChoice === "Open Markdown Report" && vscode.workspace.openTextDocument) {
        const doc = await vscode.workspace.openTextDocument({
          content: markdown,
          language: "markdown",
        });
        await vscode.window.showTextDocument(doc);
      } else if (exportChoice === "Open JSON Report" && vscode.workspace.openTextDocument) {
        const doc = await vscode.workspace.openTextDocument({
          content: JSON.stringify(report, null, 2),
          language: "json",
        });
        await vscode.window.showTextDocument(doc);
      }

      return { gated: false, report, markdown, panel };
    }

    // Inline Quick Fix CodeActionProvider for TokenGuard secret diagnostics
    const quickFixProvider = {
      provideCodeActions(document, _range, actionContext) {
        const actions = [];
        const tgDiags = (actionContext.diagnostics || []).filter((d) => d.source === "TokenGuard");
        for (const diag of tgDiags) {
          const lineNum = diag.range.start.line;
          const lineObj = document.lineAt(lineNum);
          const lineText = lineObj.text;
          const rawSecret = document.getText(diag.range);
          const ruleId = String(diag.code || "ENV_SECRET");
          const envVar = suggestEnvVarName(ruleId, lineText);
          const envExpr = getEnvReplacement(document.languageId, envVar);

          // Fix 1: Replace hardcoded secret with env var lookup
          const envAction = new vscode.CodeAction(
            `TokenGuard: Replace hardcoded secret with ${envExpr}`,
            vscode.CodeActionKind.QuickFix
          );
          envAction.diagnostics = [diag];
          envAction.isPreferred = true;
          const envEdit = new vscode.WorkspaceEdit();
          // Expand range to include surrounding quotes if secret is a quoted literal in code
          let replaceRange = diag.range;
          if (
            document.languageId !== "dotenv" &&
            diag.range.start.line === diag.range.end.line &&
            diag.range.start.character > 0 &&
            diag.range.end.character < lineText.length
          ) {
            const beforeCh = lineText[diag.range.start.character - 1];
            const afterCh = lineText[diag.range.end.character];
            if ((beforeCh === '"' && afterCh === '"') || (beforeCh === "'" && afterCh === "'")) {
              replaceRange = new vscode.Range(
                new vscode.Position(lineNum, diag.range.start.character - 1),
                new vscode.Position(lineNum, diag.range.end.character + 1)
              );
            }
          }
          envEdit.replace(document.uri, replaceRange, envExpr);
          envAction.edit = envEdit;
          actions.push(envAction);

          // Fix 2: Redact in-place with reversible [[SECRET_...]] token
          const redactTag = ruleId.replace(/_KEY$|_TOKEN$/, "");
          const placeholder = vault.getOrCreatePlaceholder(redactTag, rawSecret);
          const redactAction = new vscode.CodeAction(
            `TokenGuard: Redact in-place with ${placeholder}`,
            vscode.CodeActionKind.QuickFix
          );
          redactAction.diagnostics = [diag];
          const redactEdit = new vscode.WorkspaceEdit();
          redactEdit.replace(document.uri, diag.range, placeholder);
          redactAction.edit = redactEdit;
          actions.push(redactAction);

          // Fix 3: Suppress warning on this line
          const commentPrefix = getLineCommentPrefix(document.languageId);
          const ignoreAction = new vscode.CodeAction(
            `TokenGuard: Ignore this line (${commentPrefix} tokenguard-ignore)`,
            vscode.CodeActionKind.QuickFix
          );
          ignoreAction.diagnostics = [diag];
          const ignoreEdit = new vscode.WorkspaceEdit();
          ignoreEdit.insert(
            document.uri,
            new vscode.Position(lineNum, lineText.length),
            ` ${commentPrefix} tokenguard-ignore`
          );
          ignoreAction.edit = ignoreEdit;
          actions.push(ignoreAction);
        }
        return actions;
      },
    };

    const disposables = [
      statusBarItem,
      diagnostics,
      vscode.commands.registerCommand("tokenguard.copySafely", handleCopySafely),
      vscode.commands.registerCommand("tokenguard.restoreFromClipboard", handleRestoreFromClipboard),
      vscode.commands.registerCommand("tokenguard.compressJson", handleCompressJson),
      vscode.commands.registerCommand("tokenguard.expandSchema", handleExpandSchema),
      vscode.commands.registerCommand("tokenguard.showTokenBreakdown", handleShowTokenBreakdown),
      vscode.commands.registerCommand("tokenguard.clearVault", handleClearVault),
      vscode.commands.registerCommand("tokenguard.enterLicenseKey", handleEnterLicenseKey),
      vscode.commands.registerCommand("tokenguard.proWorkspaceBudget", handleProWorkspaceBudget),
      vscode.commands.registerCommand("tokenguard.proWorkspaceAudit", handleProWorkspaceAudit),
      vscode.languages.registerCodeActionsProvider(
        [{ scheme: "file" }, { scheme: "untitled" }],
        quickFixProvider,
        { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
      ),
      vscode.window.onDidChangeActiveTextEditor((editor) => updateStatusBarNow(editor)),
      vscode.window.onDidChangeTextEditorSelection((evt) => scheduleUpdate(evt.textEditor)),
      vscode.workspace.onDidChangeTextDocument((evt) => {
        const active = vscode.window.activeTextEditor;
        if (active && active.document === evt.document) {
          scheduleUpdate(active);
        } else {
          updateDiagnosticsForDocument(evt.document);
        }
      }),
      vscode.workspace.onDidCloseTextDocument((doc) => diagnostics.delete(doc.uri)),
      vscode.workspace.onDidChangeConfiguration((evt) => {
        if (evt && typeof evt.affectsConfiguration === "function" && !evt.affectsConfiguration("tokenguard")) {
          return;
        }
        updateStatusBarNow();
      }),
      {
        dispose() {
          if (debounceTimer) {
            clearTimeout(debounceTimer);
            debounceTimer = null;
          }
          vault.clear();
        },
      },
    ];

    context.subscriptions.push(...disposables);

    // Initialize license state and initial status bar/diagnostics
    refreshLicenseState().then(() => updateStatusBarNow());

    return {
      vault,
      diagnostics,
      statusBarItem,
      quickFixProvider,
      updateStatusBarNow,
      refreshLicenseState,
    };
  }

  function deactivate() {
    // Cleanup handled via context.subscriptions
  }

  return { activate, deactivate };
}

let vscodeApi = null;
try {
  vscodeApi = require("vscode");
} catch (_) {
  vscodeApi = null;
}

if (vscodeApi) {
  const ext = createExtension(vscodeApi);
  module.exports = {
    activate: ext.activate,
    deactivate: ext.deactivate,
    createExtension,
  };
} else {
  module.exports = { createExtension };
}
