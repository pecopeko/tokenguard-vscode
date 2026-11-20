"use strict";

const crypto = require("crypto");

/**
 * Offline Ed25519 asymmetric Pro license key verifier for TokenGuard.
 *
 * Key format:
 *   TGPRO-<base64url(JSON payload)>.<base64url(64-byte Ed25519 signature over "TGPRO-" + payloadB64)>
 *
 * Security model:
 * - Only the Ed25519 SPKI PUBLIC key ships inside the extension (.vsix).
 * - Verification runs 100% offline using Node.js native `crypto.verify`.
 * - Zero backend server, zero telemetry, zero possibility of forging valid keys without the private key.
 * - Replace DEFAULT_PUBLIC_KEY_PEM via `node tools/keygen.mjs init` before official Marketplace publish.
 */

const LICENSE_PREFIX = "TGPRO-";
const PRODUCT_ID = "tokenguard-pro";
const VALID_PLANS = new Set(["pro-monthly", "pro-lifetime", "team"]);
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

const DEFAULT_PUBLIC_KEY_PEM = [
  "-----BEGIN PUBLIC KEY-----",
  "MCowBQYDK2VwAyEAnMB92FBCZOeSExhcnTi08QppK+R1RagukirXoqxE4xw=",
  "-----END PUBLIC KEY-----",
].join("\n");

/**
 * Validate a TokenGuard Pro license key offline using Ed25519.
 *
 * @param {string} rawKey
 * @param {{ publicKeyPem?: string, now?: Date | number }} [options]
 * @returns {{
 *   valid: boolean,
 *   tier: "pro" | "free",
 *   reason: string,
 *   payload: {
 *     v: number,
 *     product: string,
 *     plan: string,
 *     email: string,
 *     issuedAt: string,
 *     expiresAt: string | null,
 *     seats: number,
 *     id?: string
 *   } | null
 * }}
 */
function verifyLicenseKey(rawKey, options = {}) {
  if (typeof rawKey !== "string" || rawKey.trim().length === 0) {
    return { valid: false, tier: "free", reason: "empty_key", payload: null };
  }

  const trimmed = rawKey.trim();
  if (!trimmed.startsWith(LICENSE_PREFIX)) {
    return { valid: false, tier: "free", reason: "invalid_prefix", payload: null };
  }

  const body = trimmed.slice(LICENSE_PREFIX.length);
  const parts = body.split(".");
  if (parts.length !== 2) {
    return { valid: false, tier: "free", reason: "malformed_format", payload: null };
  }

  const [payloadB64, sigB64] = parts;
  if (!payloadB64 || !sigB64 || !BASE64URL_RE.test(payloadB64) || !BASE64URL_RE.test(sigB64)) {
    return { valid: false, tier: "free", reason: "invalid_encoding", payload: null };
  }

  const signature = Buffer.from(sigB64, "base64url");
  if (signature.length !== 64) {
    return { valid: false, tier: "free", reason: "invalid_signature_length", payload: null };
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey(options.publicKeyPem || DEFAULT_PUBLIC_KEY_PEM);
    if (publicKey.asymmetricKeyType !== "ed25519") {
      return { valid: false, tier: "free", reason: "unsupported_key_type", payload: null };
    }
  } catch (_) {
    return { valid: false, tier: "free", reason: "invalid_public_key", payload: null };
  }

  const signingInput = Buffer.from(`${LICENSE_PREFIX}${payloadB64}`, "utf8");
  let signatureValid = false;
  try {
    signatureValid = crypto.verify(null, signingInput, publicKey, signature);
  } catch (_) {
    signatureValid = false;
  }

  if (!signatureValid) {
    return { valid: false, tier: "free", reason: "invalid_signature", payload: null };
  }

  let payload;
  try {
    const jsonText = Buffer.from(payloadB64, "base64url").toString("utf8");
    payload = JSON.parse(jsonText);
  } catch (_) {
    return { valid: false, tier: "free", reason: "invalid_payload_json", payload: null };
  }

  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { valid: false, tier: "free", reason: "invalid_payload_schema", payload: null };
  }
  if (payload.v !== 1 || payload.product !== PRODUCT_ID) {
    return { valid: false, tier: "free", reason: "wrong_product_or_version", payload: null };
  }
  if (!VALID_PLANS.has(payload.plan)) {
    return { valid: false, tier: "free", reason: "invalid_plan", payload: null };
  }
  if (typeof payload.email !== "string" || !payload.email.includes("@") || payload.email.length < 5) {
    return { valid: false, tier: "free", reason: "invalid_email", payload: null };
  }
  const issuedMs = Date.parse(payload.issuedAt);
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, tier: "free", reason: "invalid_issued_at", payload: null };
  }
  const seats = payload.seats === undefined ? 1 : payload.seats;
  if (!Number.isInteger(seats) || seats < 1 || seats > 10000) {
    return { valid: false, tier: "free", reason: "invalid_seats", payload: null };
  }

  const nowMs =
    options.now instanceof Date
      ? options.now.getTime()
      : typeof options.now === "number"
        ? options.now
        : Date.now();

  if (payload.expiresAt !== null && payload.expiresAt !== undefined) {
    const expiresMs = Date.parse(payload.expiresAt);
    if (!Number.isFinite(expiresMs)) {
      return { valid: false, tier: "free", reason: "invalid_expires_at", payload: null };
    }
    if (expiresMs <= nowMs) {
      return {
        valid: false,
        tier: "free",
        reason: "expired",
        payload: { ...payload, seats },
      };
    }
  }

  return {
    valid: true,
    tier: "pro",
    reason: "ok",
    payload: {
      v: 1,
      product: PRODUCT_ID,
      plan: payload.plan,
      email: payload.email,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt === undefined ? null : payload.expiresAt,
      seats,
      id: payload.id || undefined,
    },
  };
}

/**
 * Format human-readable license status for notifications and tooltips.
 *
 * @param {ReturnType<typeof verifyLicenseKey>} verification
 * @returns {string}
 */
function formatLicenseSummary(verification) {
  if (!verification || !verification.valid || !verification.payload) {
    if (verification && verification.reason === "expired" && verification.payload) {
      return `Expired (${verification.payload.email} · expired ${verification.payload.expiresAt})`;
    }
    return "Free Tier";
  }
  const { plan, email, expiresAt, seats } = verification.payload;
  const planLabel =
    plan === "pro-lifetime"
      ? "Pro Lifetime"
      : plan === "team"
        ? `Pro Team (${seats} seats)`
        : "Pro Monthly";
  const expiryLabel = expiresAt ? `valid until ${expiresAt.slice(0, 10)}` : "never expires";
  return `${planLabel} · ${email} (${expiryLabel})`;
}

module.exports = {
  LICENSE_PREFIX,
  PRODUCT_ID,
  VALID_PLANS,
  DEFAULT_PUBLIC_KEY_PEM,
  verifyLicenseKey,
  formatLicenseSummary,
};
