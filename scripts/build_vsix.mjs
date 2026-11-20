#!/usr/bin/env node
/**
 * Deterministic, zero-dependency OPC `.vsix` builder for TokenGuard.
 * Generates a fully compliant VS Code / Cursor / Windsurf / Open VSX `.vsix` archive
 * containing `[Content_Types].xml`, `extension.vsixmanifest`, and `extension/**`.
 */

import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXT_ROOT = path.resolve(__dirname, "..");

// Standard IEEE 802.3 CRC-32 lookup table
const CRC_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n += 1) {
  let c = n;
  for (let k = 0; k < 8; k += 1) {
    c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[n] = c >>> 0;
}

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Assemble a deterministic PKZIP archive buffer (UTF-8 filenames, Deflate or Store).
 *
 * @param {Array<{ name: string, data: Buffer }>} entries
 * @returns {Buffer}
 */
function buildZipBuffer(entries) {
  // Deterministic DOS timestamp: 2026-11-20 00:00:00
  const dosTime = 0x0000;
  const dosDate = ((2026 - 1980) << 9) | (11 << 5) | 20;

  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name.replace(/\\/g, "/"), "utf8");
    const rawData = entry.data;
    const checksum = crc32(rawData);

    const ext = path.extname(entry.name).toLowerCase();
    const shouldStore = ext === ".png" || ext === ".jpg" || rawData.length === 0;
    const compressedData = shouldStore ? rawData : zlib.deflateRawSync(rawData, { level: 9 });
    const method = shouldStore ? 0 : 8;

    // Local File Header (30 bytes + filename)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed (2.0)
    localHeader.writeUInt16LE(0x0800, 6); // general purpose bit flag (UTF-8)
    localHeader.writeUInt16LE(method, 8); // compression method
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(checksum, 14);
    localHeader.writeUInt32LE(compressedData.length, 18);
    localHeader.writeUInt32LE(rawData.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra field length

    localParts.push(localHeader, nameBuf, compressedData);

    // Central Directory Header (46 bytes + filename)
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE((3 << 8) | 20, 4); // version made by (UNIX, 2.0)
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(0x0800, 8); // UTF-8 flag
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(checksum, 16);
    centralHeader.writeUInt32LE(compressedData.length, 20);
    centralHeader.writeUInt32LE(rawData.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30); // extra length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk number
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attrs (regular file)
    centralHeader.writeUInt32LE(offset, 42); // relative offset of local header

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressedData.length;
  }

  const centralDirBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4); // disk num
  eocd.writeUInt16LE(0, 6); // start disk
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, centralDirBuf, eocd]);
}

function escapeXml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function compileIgnorePattern(pattern) {
  let p = pattern.trim();
  if (!p || p.startsWith("#")) return null;
  if (p.endsWith("/**")) {
    const dir = p.slice(0, -3).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    return new RegExp(`^${dir}(?:/.*)?$`);
  }
  const escaped = p
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, ".*")
    .replace(/\*/g, "[^/]*");
  if (p.includes("/")) {
    return new RegExp(`^${escaped}$`);
  }
  return new RegExp(`(?:^|/)${escaped}$`);
}

function loadIgnoreMatchers(rootDir) {
  const ignorePath = path.join(rootDir, ".vscodeignore");
  const lines = fs.existsSync(ignorePath) ? fs.readFileSync(ignorePath, "utf8").split(/\r?\n/) : [];
  // Hardcoded mandatory security exclusions (never bundle creator tools, keys, tests, or nested VSIX)
  const mandatory = [
    ".git/**",
    ".vscodeignore",
    ".gitignore",
    ".DS_Store",
    "tools/**",
    "scripts/**",
    "test/**",
    "*.vsix",
    "*.pem",
    "*.key",
    "MARKETPLACE_PUBLISH_GUIDE.md",
  ];
  return [...lines, ...mandatory].map(compileIgnorePattern).filter(Boolean);
}

function collectPackageFiles(rootDir) {
  const ignoreMatchers = loadIgnoreMatchers(rootDir);
  const collected = [];

  function walk(absDir, relDir) {
    const entries = fs.readdirSync(absDir, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const relPosix = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (ignoreMatchers.some((re) => re.test(relPosix))) {
        continue;
      }
      const absPath = path.join(absDir, entry.name);
      if (entry.isDirectory()) {
        walk(absPath, relPosix);
      } else if (entry.isFile()) {
        const data = fs.readFileSync(absPath);
        // Hard security invariant: never package any private key PEM block
        if (
          !relPosix.endsWith(".png") &&
          /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(data.toString("utf8"))
        ) {
          throw new Error(`SECURITY BLOCK: Refusing to package file containing a PRIVATE KEY block: ${relPosix}`);
        }
        collected.push({ relPosix, absPath, data });
      }
    }
  }

  walk(rootDir, "");
  return collected;
}

function buildContentTypesXml(archiveEntries) {
  const mimeMap = {
    vsixmanifest: "text/xml",
    json: "application/json",
    js: "application/javascript",
    cjs: "application/javascript",
    mjs: "application/javascript",
    md: "text/markdown",
    png: "image/png",
    svg: "image/svg+xml",
    txt: "text/plain",
    css: "text/css",
    html: "text/html",
  };

  const seenExts = new Set(["vsixmanifest"]);
  const overrides = [];

  for (const entry of archiveEntries) {
    const base = path.posix.basename(entry.name);
    const dotIdx = base.lastIndexOf(".");
    if (dotIdx <= 0) {
      overrides.push({
        partName: `/${entry.name}`,
        contentType: "text/plain",
      });
    } else {
      const ext = base.slice(dotIdx + 1).toLowerCase();
      seenExts.add(ext);
    }
  }

  const defaultsXml = Array.from(seenExts)
    .sort()
    .map(
      (ext) =>
        `  <Default Extension="${escapeXml(ext)}" ContentType="${escapeXml(mimeMap[ext] || "application/octet-stream")}"/>`
    )
    .join("\n");

  const overridesXml = overrides
    .map(
      (ov) =>
        `  <Override PartName="${escapeXml(ov.partName)}" ContentType="${escapeXml(ov.contentType)}"/>`
    )
    .join("\n");

  return [
    `<?xml version="1.0" encoding="utf-8"?>`,
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`,
    defaultsXml,
    overridesXml,
    `</Types>`,
    ``,
  ]
    .filter(Boolean)
    .join("\n");
}

function buildVsixManifestXml(pkg, packagedPaths) {
  const repoUrl = typeof pkg.repository === "string" ? pkg.repository : pkg.repository?.url || "";
  const cleanRepoUrl = repoUrl.replace(/\.git$/, "");
  const bugsUrl = typeof pkg.bugs === "string" ? pkg.bugs : pkg.bugs?.url || `${cleanRepoUrl}/issues`;
  const tags = Array.isArray(pkg.keywords) ? pkg.keywords.join(",") : "";
  const categories = Array.isArray(pkg.categories) ? pkg.categories.join(",") : "Other";
  const bannerColor = pkg.galleryBanner?.color || "#0F172A";
  const bannerTheme = pkg.galleryBanner?.theme || "dark";

  const hasFile = (rel) => packagedPaths.has(rel);

  const assets = [
    `    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />`,
  ];
  if (hasFile("README.md")) {
    assets.push(
      `    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />`
    );
  }
  if (hasFile("CHANGELOG.md")) {
    assets.push(
      `    <Asset Type="Microsoft.VisualStudio.Services.Content.Changelog" Path="extension/CHANGELOG.md" Addressable="true" />`
    );
  }
  if (hasFile("LICENSE")) {
    assets.push(
      `    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE" Addressable="true" />`
    );
  }
  if (pkg.icon && hasFile(pkg.icon)) {
    assets.push(
      `    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="extension/${escapeXml(pkg.icon)}" Addressable="true" />`
    );
  }

  return `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="${escapeXml(pkg.name)}" Version="${escapeXml(pkg.version)}" Publisher="${escapeXml(pkg.publisher)}" />
    <DisplayName>${escapeXml(pkg.displayName || pkg.name)}</DisplayName>
    <Description xml:space="preserve">${escapeXml(pkg.description || "")}</Description>
    <Tags>${escapeXml(tags)}</Tags>
    <Categories>${escapeXml(categories)}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="${escapeXml(pkg.engines?.vscode || "^1.85.0")}" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Source" Value="${escapeXml(cleanRepoUrl)}" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Getstarted" Value="${escapeXml(cleanRepoUrl)}" />
      <Property Id="Microsoft.VisualStudio.Services.Links.GitHub" Value="${escapeXml(cleanRepoUrl)}" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Support" Value="${escapeXml(bugsUrl)}" />
      <Property Id="Microsoft.VisualStudio.Services.Branding.Color" Value="${escapeXml(bannerColor)}" />
      <Property Id="Microsoft.VisualStudio.Services.Branding.Theme" Value="${escapeXml(bannerTheme)}" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
    </Properties>
    ${hasFile("LICENSE") ? `<License>extension/LICENSE</License>` : ""}
    ${pkg.icon && hasFile(pkg.icon) ? `<Icon>extension/${escapeXml(pkg.icon)}</Icon>` : ""}
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" />
  </Installation>
  <Dependencies />
  <Assets>
${assets.join("\n")}
  </Assets>
</PackageManifest>
`;
}

export function buildVsix(rootDir = EXT_ROOT, outputPath = null) {
  const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, "package.json"), "utf8"));
  if (!pkg.name || !pkg.version || !pkg.publisher) {
    throw new Error("package.json must declare name, version, and publisher");
  }
  if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) {
    throw new Error("Zero-dependency invariant violated: package.json dependencies must be empty");
  }

  const files = collectPackageFiles(rootDir);
  const packagedSet = new Set(files.map((f) => f.relPosix));

  for (const required of ["package.json", "extension.js", "README.md", "LICENSE", pkg.icon]) {
    if (required && !packagedSet.has(required)) {
      throw new Error(`Missing required packaged extension file: ${required}`);
    }
  }

  const extensionEntries = files.map((f) => ({
    name: `extension/${f.relPosix}`,
    data: f.data,
  }));

  const manifestXml = buildVsixManifestXml(pkg, packagedSet);
  const manifestEntry = {
    name: "extension.vsixmanifest",
    data: Buffer.from(manifestXml, "utf8"),
  };

  const contentTypesXml = buildContentTypesXml([manifestEntry, ...extensionEntries]);
  const contentTypesEntry = {
    name: "[Content_Types].xml",
    data: Buffer.from(contentTypesXml, "utf8"),
  };

  const allEntries = [contentTypesEntry, manifestEntry, ...extensionEntries];
  const zipBuf = buildZipBuffer(allEntries);

  const outFile = outputPath
    ? path.resolve(outputPath)
    : path.join(rootDir, `${pkg.name}-${pkg.version}.vsix`);
  fs.writeFileSync(outFile, zipBuf);

  return {
    outputPath: outFile,
    bytes: zipBuf.length,
    entries: allEntries.map((e) => e.name),
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (isMain) {
  const res = buildVsix(EXT_ROOT);
  console.log(`Built ${path.basename(res.outputPath)} (${res.bytes.toLocaleString("en-US")} bytes, ${res.entries.length} entries):`);
  for (const name of res.entries) {
    console.log(`  - ${name}`);
  }
}
