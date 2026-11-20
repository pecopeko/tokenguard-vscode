#!/usr/bin/env node
/**
 * Creator-only offline Ed25519 license key generator for TokenGuard Pro.
 * NEVER bundled into the .vsix package (excluded via .vscodeignore).
 *
 * Usage:
 *   node tools/keygen.mjs init --out ~/.tokenguard/issuer.private.pem
 *   node tools/keygen.mjs sign --key ~/.tokenguard/issuer.private.pem --email dev@example.com --plan pro-lifetime
 *   node tools/keygen.mjs sign --key ~/.tokenguard/issuer.private.pem --email dev@example.com --plan pro-monthly --expires 2027-12-31T23:59:59Z
 *   node tools/keygen.mjs verify --key <public-or-private.pem> --license TGPRO-...
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const {
  LICENSE_PREFIX,
  PRODUCT_ID,
  VALID_PLANS,
  verifyLicenseKey,
  formatLicenseSummary,
} = require("../src/core/license.js");

/**
 * Generate a fresh Ed25519 keypair in PEM format.
 *
 * @returns {{ publicKeyPem: string, privateKeyPem: string }}
 */
export function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/**
 * Mint an offline-verifiable Ed25519-signed TokenGuard Pro license key.
 *
 * @param {{
 *   privateKeyPem: string,
 *   email: string,
 *   plan?: "pro-monthly" | "pro-lifetime" | "team",
 *   expiresAt?: string | null,
 *   issuedAt?: string,
 *   seats?: number,
 *   id?: string
 * }} params
 * @returns {{ licenseKey: string, payload: object }}
 */
export function mintLicenseKey({
  privateKeyPem,
  email,
  plan = "pro-lifetime",
  expiresAt = null,
  issuedAt = new Date().toISOString(),
  seats = 1,
  id = `lic_${crypto.randomBytes(6).toString("hex")}`,
}) {
  if (!privateKeyPem) {
    throw new Error("privateKeyPem is required");
  }
  if (!email || !email.includes("@")) {
    throw new Error("A valid customer email is required");
  }
  if (!VALID_PLANS.has(plan)) {
    throw new Error(`Invalid plan "${plan}". Expected one of: ${Array.from(VALID_PLANS).join(", ")}`);
  }

  let normalizedExpiresAt = null;
  if (expiresAt !== null && expiresAt !== undefined && String(expiresAt).trim() !== "") {
    const parsed = Date.parse(expiresAt);
    if (!Number.isFinite(parsed)) {
      throw new Error(`Invalid expiresAt timestamp: ${expiresAt}`);
    }
    normalizedExpiresAt = new Date(parsed).toISOString();
  }

  const payload = {
    v: 1,
    product: PRODUCT_ID,
    plan,
    email: email.trim(),
    issuedAt: new Date(Date.parse(issuedAt)).toISOString(),
    expiresAt: normalizedExpiresAt,
    seats: Number(seats) || 1,
    id,
  };

  const payloadB64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signingInput = Buffer.from(`${LICENSE_PREFIX}${payloadB64}`, "utf8");
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const signature = crypto.sign(null, signingInput, privateKey);
  const sigB64 = signature.toString("base64url");

  return {
    licenseKey: `${LICENSE_PREFIX}${payloadB64}.${sigB64}`,
    payload,
  };
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        args[key] = next;
        i += 1;
      } else {
        args[key] = true;
      }
    } else {
      args._.push(token);
    }
  }
  return args;
}

function runCli(argv) {
  const args = parseArgs(argv);
  const cmd = args._[0];

  if (cmd === "init") {
    const outPath = args.out ? path.resolve(args.out) : null;
    const { publicKeyPem, privateKeyPem } = generateKeyPair();
    if (outPath) {
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, privateKeyPem, { encoding: "utf8", mode: 0o600 });
      console.log(`Saved Ed25519 private key (0600) to: ${outPath}`);
      console.log("NEVER commit this private key to git or bundle it into .vsix!\n");
    } else {
      console.error("Error: specify --out <path-outside-repo> so the private key is safely written with 0600 permissions.");
      process.exitCode = 1;
      return;
    }
    console.log("Paste this SPKI public key into src/core/license.js (DEFAULT_PUBLIC_KEY_PEM):");
    console.log(publicKeyPem);
    return;
  }

  if (cmd === "sign") {
    const keyPath = args.key;
    const email = args.email;
    const plan = args.plan || "pro-lifetime";
    const expiresAt = args.expires || null;
    const seats = args.seats ? Number(args.seats) : 1;

    if (!keyPath || !email) {
      console.error("Usage: node tools/keygen.mjs sign --key <private.pem> --email <customer@email> [--plan pro-lifetime|pro-monthly|team] [--expires YYYY-MM-DD] [--seats 1]");
      process.exitCode = 1;
      return;
    }

    const privateKeyPem = fs.readFileSync(path.resolve(keyPath), "utf8");
    const { licenseKey, payload } = mintLicenseKey({
      privateKeyPem,
      email,
      plan,
      expiresAt,
      seats,
    });
    console.log("License Key:\n");
    console.log(licenseKey);
    console.log("\nPayload:", JSON.stringify(payload, null, 2));
    return;
  }

  if (cmd === "verify") {
    const license = args.license;
    if (!license) {
      console.error("Usage: node tools/keygen.mjs verify --license TGPRO-... [--key <public-or-private.pem>]");
      process.exitCode = 1;
      return;
    }
    let publicKeyPem;
    if (args.key) {
      const pem = fs.readFileSync(path.resolve(args.key), "utf8");
      if (pem.includes("PRIVATE KEY")) {
        publicKeyPem = crypto.createPublicKey(pem).export({ type: "spki", format: "pem" }).toString();
      } else {
        publicKeyPem = pem;
      }
    }
    const res = verifyLicenseKey(license, { publicKeyPem });
    console.log(JSON.stringify({ ...res, summary: formatLicenseSummary(res) }, null, 2));
    if (!res.valid) {
      process.exitCode = 1;
    }
    return;
  }

  console.log(`TokenGuard Pro Offline Keygen (Ed25519)
Commands:
  init   --out <path-outside-repo>
  sign   --key <private.pem> --email <email> [--plan pro-lifetime|pro-monthly|team] [--expires <ISO>] [--seats <N>]
  verify --license <TGPRO-...> [--key <public-or-private.pem>]`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runCli(process.argv.slice(2));
}
