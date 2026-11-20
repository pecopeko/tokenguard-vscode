"use strict";

/**
 * Multi-script BPE-calibrated LLM token & API cost estimator.
 * Pure CommonJS, zero runtime dependencies, O(n) single-pass performance.
 */

const FRONTIER_MODELS = Object.freeze([
  Object.freeze({
    id: "gpt-5",
    name: "GPT-5",
    provider: "OpenAI",
    inputPerMillionUsd: 1.25,
    outputPerMillionUsd: 10.0,
    contextWindow: 400000,
    tier: "flagship",
  }),
  Object.freeze({
    id: "claude-sonnet-4",
    name: "Claude Sonnet 4",
    provider: "Anthropic",
    inputPerMillionUsd: 3.0,
    outputPerMillionUsd: 15.0,
    contextWindow: 200000,
    tier: "flagship",
  }),
  Object.freeze({
    id: "gemini-2.5-pro",
    name: "Gemini 2.5 Pro",
    provider: "Google",
    inputPerMillionUsd: 1.25,
    outputPerMillionUsd: 10.0,
    contextWindow: 1000000,
    tier: "flagship",
  }),
  Object.freeze({
    id: "gpt-4o-mini",
    name: "GPT-4o mini",
    provider: "OpenAI",
    inputPerMillionUsd: 0.15,
    outputPerMillionUsd: 0.6,
    contextWindow: 128000,
    tier: "fast",
  }),
  Object.freeze({
    id: "claude-haiku-4.5",
    name: "Claude Haiku 4.5",
    provider: "Anthropic",
    inputPerMillionUsd: 0.8,
    outputPerMillionUsd: 4.0,
    contextWindow: 200000,
    tier: "fast",
  }),
  Object.freeze({
    id: "gemini-2.5-flash",
    name: "Gemini 2.5 Flash",
    provider: "Google",
    inputPerMillionUsd: 0.15,
    outputPerMillionUsd: 0.6,
    contextWindow: 1000000,
    tier: "fast",
  }),
]);

const MODEL_MAP = new Map(FRONTIER_MODELS.map((m) => [m.id, m]));

function isAsciiLetter(cp) {
  return (cp >= 65 && cp <= 90) || (cp >= 97 && cp <= 122);
}

function isAsciiDigit(cp) {
  return cp >= 48 && cp <= 57;
}

function isHiraganaOrKatakana(cp) {
  return (
    (cp >= 0x3040 && cp <= 0x309f) ||
    (cp >= 0x30a0 && cp <= 0x30ff) ||
    (cp >= 0xff65 && cp <= 0xff9f)
  );
}

function isCjkIdeograph(cp) {
  return (
    (cp >= 0x4e00 && cp <= 0x9fff) ||
    (cp >= 0x3400 && cp <= 0x4dbf) ||
    (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0x3000 && cp <= 0x303f)
  );
}

function isHangul(cp) {
  return (
    (cp >= 0xac00 && cp <= 0xd7af) ||
    (cp >= 0x1100 && cp <= 0x11ff) ||
    (cp >= 0x3130 && cp <= 0x318f)
  );
}

function isFullWidthAsciiOrPunct(cp) {
  return cp >= 0xff01 && cp <= 0xff60;
}

function estimateWordTokens(word) {
  if (!word) {
    return 0;
  }
  // Split camelCase / PascalCase / snake_case identifiers into realistic BPE subwords
  const subParts = word
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/_+/g, " _ ")
    .split(" ")
    .filter(Boolean);

  let total = 0;
  for (let i = 0; i < subParts.length; i += 1) {
    const part = subParts[i];
    if (part === "_") {
      total += 0.35;
    } else if (part.length <= 4) {
      total += 1.0;
    } else if (part.length <= 8) {
      total += 1.25;
    } else {
      total += Math.ceil(part.length / 4.2);
    }
  }
  return total;
}

/**
 * Estimate LLM token count and script composition for arbitrary text/code.
 * Calibrated against o200k_base / cl100k_base / Claude BPE token densities across
 * English prose, source code, JSON, Japanese (Hiragana/Katakana/Kanji), Chinese, Korean, and Emoji.
 *
 * @param {string} text
 * @returns {{
 *   tokens: number,
 *   characters: number,
 *   lines: number,
 *   bytes: number,
 *   dominantScript: string,
 *   breakdown: {
 *     asciiWords: number,
 *     digits: number,
 *     kanaChars: number,
 *     cjkChars: number,
 *     hangulChars: number,
 *     otherUnicode: number,
 *     symbols: number,
 *     whitespaceRuns: number,
 *     emoji: number
 *   }
 * }}
 */
function estimateTokens(text) {
  if (typeof text !== "string" || text.length === 0) {
    return {
      tokens: 0,
      characters: 0,
      lines: 0,
      bytes: 0,
      dominantScript: "empty",
      breakdown: {
        asciiWords: 0,
        digits: 0,
        kanaChars: 0,
        cjkChars: 0,
        hangulChars: 0,
        otherUnicode: 0,
        symbols: 0,
        whitespaceRuns: 0,
        emoji: 0,
      },
    };
  }

  let tokenFloat = 0;
  let lines = 1;
  const breakdown = {
    asciiWords: 0,
    digits: 0,
    kanaChars: 0,
    cjkChars: 0,
    hangulChars: 0,
    otherUnicode: 0,
    symbols: 0,
    whitespaceRuns: 0,
    emoji: 0,
  };

  const len = text.length;
  let i = 0;

  while (i < len) {
    const cp = text.codePointAt(i);
    const charStep = cp > 0xffff ? 2 : 1;

    // 1. ASCII identifier / word run
    if (isAsciiLetter(cp)) {
      const start = i;
      i += 1;
      while (i < len) {
        const nextCp = text.charCodeAt(i);
        if (isAsciiLetter(nextCp) || nextCp === 95 || nextCp === 39) {
          i += 1;
        } else {
          break;
        }
      }
      const word = text.slice(start, i);
      breakdown.asciiWords += 1;
      tokenFloat += estimateWordTokens(word);
      continue;
    }

    // 2. Numeric run (BPE merges up to 3 digits per token)
    if (isAsciiDigit(cp)) {
      const start = i;
      i += 1;
      while (i < len && isAsciiDigit(text.charCodeAt(i))) {
        i += 1;
      }
      const digitCount = i - start;
      breakdown.digits += digitCount;
      tokenFloat += Math.ceil(digitCount / 3);
      continue;
    }

    // 3. Newlines
    if (cp === 10) {
      lines += 1;
      breakdown.whitespaceRuns += 1;
      tokenFloat += 0.65;
      i += 1;
      continue;
    }
    if (cp === 13) {
      i += 1;
      continue;
    }

    // 4. Horizontal whitespace runs (indentation collapses efficiently in BPE)
    if (cp === 32 || cp === 9) {
      const start = i;
      while (i < len && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) {
        i += 1;
      }
      const runLen = i - start;
      breakdown.whitespaceRuns += 1;
      // Single space between words usually merges into next word token (~0.08 extra)
      if (runLen === 1) {
        tokenFloat += 0.08;
      } else {
        tokenFloat += Math.ceil(runLen / 4) * 0.85;
      }
      continue;
    }

    // 5. ASCII punctuation / JSON & code syntax symbols
    if (cp >= 33 && cp <= 126) {
      const start = i;
      i += 1;
      // Pair common multi-char code/JSON operators (":", "=>", "==", "//", "/*", "*/", "&&", "||", "[[", "]]")
      if (i < len) {
        const nextCp = text.charCodeAt(i);
        const pair = text.slice(start, start + 2);
        if (
          pair === '":' ||
          pair === '",' ||
          pair === '"}' ||
          pair === '"]' ||
          pair === "=>" ||
          pair === "==" ||
          pair === "!=" ||
          pair === "<=" ||
          pair === ">=" ||
          pair === "&&" ||
          pair === "||" ||
          pair === "//" ||
          pair === "/*" ||
          pair === "*/" ||
          pair === "::" ||
          pair === "->" ||
          pair === "[]" ||
          pair === "{}" ||
          (nextCp === cp && (cp === 45 || cp === 61 || cp === 91 || cp === 93))
        ) {
          i += 1;
          breakdown.symbols += 2;
          tokenFloat += 0.95;
          continue;
        }
      }
      breakdown.symbols += 1;
      tokenFloat += 0.65;
      continue;
    }

    // 6. Japanese Hiragana & Katakana (~1.15 tok/char)
    if (isHiraganaOrKatakana(cp)) {
      breakdown.kanaChars += 1;
      tokenFloat += 1.15;
      i += charStep;
      continue;
    }

    // 7. CJK Ideographs / Kanji & CJK punctuation (~1.45 tok/char)
    if (isCjkIdeograph(cp)) {
      breakdown.cjkChars += 1;
      tokenFloat += 1.45;
      i += charStep;
      continue;
    }

    // 8. Korean Hangul (~1.25 tok/char)
    if (isHangul(cp)) {
      breakdown.hangulChars += 1;
      tokenFloat += 1.25;
      i += charStep;
      continue;
    }

    // 9. Full-width punctuation/alphanumerics
    if (isFullWidthAsciiOrPunct(cp)) {
      breakdown.otherUnicode += 1;
      tokenFloat += 1.2;
      i += charStep;
      continue;
    }

    // 10. Astral plane / Emoji (typically 2-3 BPE bytes/tokens)
    if (cp > 0xffff) {
      breakdown.emoji += 1;
      tokenFloat += 2.3;
      i += charStep;
      continue;
    }

    // 11. Other BMP Unicode (accented Latin, Cyrillic, Greek, Arabic, etc.)
    breakdown.otherUnicode += 1;
    tokenFloat += 0.95;
    i += charStep;
  }

  const tokens = Math.max(1, Math.round(tokenFloat));
  const bytes = Buffer.byteLength(text, "utf8");

  let dominantScript = "en-code";
  const jpTotal = breakdown.kanaChars + breakdown.cjkChars;
  if (breakdown.kanaChars > 0 && jpTotal >= Math.max(4, breakdown.asciiWords * 0.5)) {
    dominantScript = "ja-mixed";
  } else if (breakdown.cjkChars > 0 && breakdown.cjkChars >= Math.max(4, breakdown.asciiWords * 0.5)) {
    dominantScript = "cjk-mixed";
  } else if (breakdown.hangulChars > 0 && breakdown.hangulChars >= Math.max(4, breakdown.asciiWords * 0.5)) {
    dominantScript = "ko-mixed";
  }

  return {
    tokens,
    characters: text.length,
    lines,
    bytes,
    dominantScript,
    breakdown,
  };
}

/**
 * Look up a model definition by ID, falling back to Claude Sonnet 4 if unknown.
 *
 * @param {string} modelId
 */
function getModel(modelId) {
  return MODEL_MAP.get(modelId) || MODEL_MAP.get("claude-sonnet-4");
}

/**
 * Estimate input and hypothetical 1:1 output USD cost for a token count on one model.
 *
 * @param {number} tokens
 * @param {string} modelId
 */
function calculateModelCost(tokens, modelId) {
  const model = getModel(modelId);
  const safeTokens = Math.max(0, Number(tokens) || 0);
  const inputCostUsd = (safeTokens / 1_000_000) * model.inputPerMillionUsd;
  const outputCostUsd = (safeTokens / 1_000_000) * model.outputPerMillionUsd;
  const contextPercent = (safeTokens / model.contextWindow) * 100;
  return {
    modelId: model.id,
    modelName: model.name,
    provider: model.provider,
    tier: model.tier,
    tokens: safeTokens,
    inputPerMillionUsd: model.inputPerMillionUsd,
    outputPerMillionUsd: model.outputPerMillionUsd,
    inputCostUsd,
    outputCostUsd,
    contextWindow: model.contextWindow,
    contextPercent,
    fitsContext: safeTokens <= model.contextWindow,
  };
}

/**
 * Compute cost matrix across all 6 frontier models.
 *
 * @param {number} tokens
 */
function calculateAllModelCosts(tokens) {
  return FRONTIER_MODELS.map((m) => calculateModelCost(tokens, m.id));
}

/**
 * Format USD currency cleanly for status bar & reports (sub-cent precision for small snippets).
 *
 * @param {number} usd
 * @returns {string}
 */
function formatUsd(usd) {
  const val = Number(usd) || 0;
  if (val === 0) {
    return "$0.0000";
  }
  if (val < 0.0001) {
    return "<$0.0001";
  }
  if (val < 0.01) {
    return `$${val.toFixed(4)}`;
  }
  if (val < 1) {
    return `$${val.toFixed(3)}`;
  }
  return `$${val.toFixed(2)}`;
}

/**
 * Format compact status bar text for VS Code.
 *
 * @param {{ tokens: number, isSelection?: boolean, modelId?: string, secretCount?: number }} params
 * @returns {string}
 */
function formatStatusBarLabel({ tokens, isSelection = false, modelId = "claude-sonnet-4", secretCount = 0 }) {
  const cost = calculateModelCost(tokens, modelId);
  const formattedTokens = (Number(tokens) || 0).toLocaleString("en-US");
  const prefix = isSelection ? "Sel: " : "";
  const shieldIcon = secretCount > 0 ? "$(warning)" : "$(shield)";
  const leakTag = secretCount > 0 ? ` · ${secretCount} leak${secretCount === 1 ? "" : "s"}` : "";
  return `${shieldIcon} ${prefix}${formattedTokens} tok · ${formatUsd(cost.inputCostUsd)} (${cost.modelName})${leakTag}`;
}

module.exports = {
  FRONTIER_MODELS,
  estimateTokens,
  getModel,
  calculateModelCost,
  calculateAllModelCosts,
  formatUsd,
  formatStatusBarLabel,
};
