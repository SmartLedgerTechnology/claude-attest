#!/usr/bin/env node
/**
 * Cold path + CLI. Everything expensive lives here: key generation, ML-DSA
 * signing, the network round trip to NotaryHash, verification.
 *
 * Runs detached from the session, so a slow anchor never makes anyone wait and
 * a session exiting never truncates a finalization in flight.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { finalizeSession, readMeta } from "../src/checkpoint.mjs";
import { refreshCertificate } from "../src/anchor.mjs";
import { createIdentity, loadIdentity, identityFile, publicView } from "../src/identity.mjs";
import { home, sessionDir, loadConfig, debugLog } from "../src/paths.mjs";
import { readLeaves } from "../src/leaflog.mjs";
import { verifyAttestation } from "../packages/proof-of-process/src/verify.mjs";
import { derive } from "../packages/proof-of-process/src/profile.mjs";
import {
  buildGatheredAssertions,
  buildManifestDefinition,
  recommendDigitalSourceType,
} from "../packages/proof-of-process/src/c2pa.mjs";

const [cmd, ...args] = process.argv.slice(2);

run().catch((e) => {
  // Marketplace installs don't run `npm install`, so the signing library may be
  // absent. Capture still works without it — every hook is zero-dependency —
  // but anything that signs needs it, and a raw MODULE_NOT_FOUND stack tells
  // the user nothing about how to fix that.
  if (e?.code === "ERR_MODULE_NOT_FOUND" || /Cannot find (package|module)/.test(e?.message ?? "")) {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    console.error("This command needs the signing library, which isn't installed yet.\n");
    console.error(`  cd "${root}" && npm install --omit=dev\n`);
    console.error("Session capture already works without it — your work is being recorded.");
    console.error("Only signing, anchoring and verification need this step.");
    process.exit(1);
  }
  console.error(`error: ${e?.message ?? e}`);
  process.exit(1);
});

async function run() {
  switch (cmd) {
    case "--finalize":
    case "finalize":
      return doFinalize(args[0]);
    case "--sweep":
    case "sweep":
      return doSweep();
    case "init":
      return doInit();
    case "status":
      return doStatus();
    case "verify":
      return doVerify(args[0], args);
    case "refresh":
      return doRefresh(args[0]);
    case "publish":
      return doPublish(args[0]);
    case "c2pa":
      return doC2pa(args);
    case "list":
      return doList();
    default:
      console.log(
        [
          "claude-attest — proof of process for human-AI collaboration",
          "",
          "  init                 create a signing identity (ML-DSA-65)",
          "  status               identity, config, and anchor backend",
          "  list                 sessions captured on this machine",
          "  verify <session|path>  verify an attestation (auto-refreshes a pending anchor)",
          "  refresh <session>    pull the confirmed certificate + SPV envelope",
          "  publish <session>    host it at a shareable verify URL (subscribers)",
          "  c2pa <session>       emit C2PA assertions / a manifest definition",
          "  finalize <session>   build, sign, and anchor a session checkpoint",
          "  sweep                finalize any session left unanchored",
          "",
          "  c2pa flags: --manifest (full definition) --out <file> --title <t>",
          "              --format <mime> --verify-base <url>",
        ].join("\n")
      );
  }
}

async function doInit() {
  if (loadIdentity()) {
    console.log(`identity already exists at ${identityFile()}`);
    return doStatus();
  }
  const id = await createIdentity();
  console.log(`created ${id.algorithm} identity`);
  console.log(`  key id   ${id.publicKeyId}`);
  console.log(`  file     ${identityFile()} (mode 0600)`);
  console.log("");
  console.log("Back this file up. Losing it means you cannot sign new");
  console.log("attestations under the same identity; existing ones stay valid.");
}

async function doStatus() {
  const id = loadIdentity();
  const config = loadConfig();
  console.log(`home      ${home()}`);
  console.log(`identity  ${id ? `${id.algorithm} ${id.publicKeyId}` : "none — run `claude-attest init`"}`);
  console.log(`anchor    ${config.anchor}${config.anchor === "notaryhash" ? ` -> ${config.notaryhashUrl}` : ""}`);
  console.log(`batch     ${config.batch !== false}`);
  if (config.anchor === "notaryhash" && !config.apiKey) {
    console.log("");
    console.log("warning: NOTARYHASH_API_KEY is not set — anchoring will be rejected.");
  }
  if (id) console.log(`\npublic key\n${JSON.stringify(publicView(id), null, 2)}`);
}

function sessionsRoot() {
  return path.join(home(), "sessions");
}

async function doList() {
  const root = sessionsRoot();
  if (!fs.existsSync(root)) return console.log("no sessions captured yet");
  const rows = fs.readdirSync(root).map((id) => {
    const dir = path.join(root, id);
    const meta = readMeta(dir);
    const leaves = readLeaves(dir).length;
    const attested = fs.existsSync(path.join(dir, "attestation.json"));
    let anchored = false;
    if (attested) {
      try {
        anchored = !!JSON.parse(fs.readFileSync(path.join(dir, "attestation.json"), "utf8"))?.certificate?.anchor?.txid;
      } catch {
        anchored = false;
      }
    }
    return { id, leaves, attested, anchored, cwd: meta.cwd ?? "" };
  });
  for (const r of rows) {
    const state = r.anchored ? "anchored" : r.attested ? "signed" : "open";
    console.log(`${r.id}  ${String(r.leaves).padStart(5)} leaves  ${state.padEnd(9)} ${r.cwd}`);
  }
}

async function doFinalize(sessionId) {
  if (!sessionId) throw new Error("usage: finalize <session-id>");
  const result = await finalizeSession(sessionId);
  if (result.error) {
    debugLog(`finalize ${sessionId}: ${result.error}`);
    console.error(result.error);
    process.exit(1);
  }
  if (result.skipped) {
    console.log(`already anchored: ${result.path}`);
    return;
  }
  console.log(`${result.ok ? "anchored" : "signed (anchor failed)"}: ${result.path}`);
  if (!result.ok) console.log(`  ${result.attestation.anchorError}`);
  const txid = result.attestation.certificate?.anchor?.txid;
  if (txid) console.log(`  txid ${txid}`);
}

/**
 * Finalize every session that has leaves but no anchored attestation. Makes
 * the system self-healing after crashes, force-quits, and offline periods.
 */
async function doSweep() {
  const root = sessionsRoot();
  if (!fs.existsSync(root)) return;
  for (const id of fs.readdirSync(root)) {
    const dir = path.join(root, id);
    try {
      if (readLeaves(dir).length === 0) continue;
      const out = path.join(dir, "attestation.json");
      if (fs.existsSync(out)) {
        const existing = JSON.parse(fs.readFileSync(out, "utf8"));
        if (existing?.certificate?.anchor?.txid) continue;
        if (existing?.anchorBackend === "mock") continue;
      }
      // Never sweep the session that is currently running.
      if (id === process.env.CLAUDE_SESSION_ID) continue;
      const r = await finalizeSession(id);
      debugLog(`sweep ${id}: ${r.error ?? (r.ok ? "anchored" : "signed")}`);
    } catch (e) {
      debugLog(`sweep ${id} failed: ${e.message}`);
    }
  }
}

function resolveAttestationPath(target) {
  const file = fs.existsSync(target) ? target : path.join(sessionDir(target), "attestation.json");
  if (!fs.existsSync(file)) throw new Error(`no attestation found at ${file}`);
  return file;
}

/**
 * Pull the confirmed certificate (with its SPV envelope) from the issuing
 * service and write it back into the local attestation.
 */
async function doRefresh(target) {
  if (!target) throw new Error("usage: refresh <session-id|path-to-attestation.json>");
  const file = resolveAttestationPath(target);
  const attestation = JSON.parse(fs.readFileSync(file, "utf8"));

  const before = attestation.certificate?.anchor?.blockHeight ?? null;
  const result = await refreshCertificate(attestation, loadConfig());
  if (!result.ok) {
    console.error(result.error);
    process.exit(1);
  }

  attestation.certificate = result.certificate;
  attestation.anchorStatus = result.confirmed ? "confirmed" : "anchored";
  fs.writeFileSync(file, JSON.stringify(attestation, null, 2));

  const a = result.certificate.anchor ?? {};
  console.log(result.confirmed ? "confirmed" : "still unconfirmed");
  console.log(`  txid          ${a.txid}`);
  console.log(`  block height  ${a.blockHeight ?? "(pending)"}`);
  if (a.blockTime) console.log(`  block time    ${new Date(a.blockTime * 1000).toISOString()}`);
  console.log(`  spv envelope  ${result.certificate.spv ? "present" : "absent"}`);
  if (before === null && a.blockHeight != null) {
    console.log("\nThe local certificate now carries a full SPV envelope and can be");
    console.log("verified against Bitcoin block headers with no trust in the service.");
  }
}

/**
 * Publish an attestation to a shareable verify URL.
 *
 * Sends the header, certificate and countersignatures — never the leaves. The
 * signed header already carries the Merkle root and the collaboration profile,
 * so the page can prove everything it claims while your event log, which
 * records what you typed and ran, stays on this machine.
 */
async function doPublish(target) {
  if (!target) throw new Error("usage: publish <session-id|path-to-attestation.json>");
  const config = loadConfig();
  const apiKey = config.countersignerApiKey ?? config.apiKey;
  if (!apiKey) {
    throw new Error("publishing needs a subscription key — set COUNTERSIGNER_API_KEY (see https://proofofprocess.ai)");
  }
  const file = resolveAttestationPath(target);
  const attestation = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!attestation.certificate) throw new Error("this attestation has never been anchored; run `finalize` first");

  const base = (config.publicBase ?? "https://proofofprocess.ai").replace(/\/$/, "");
  const res = await fetch(`${base}/v1/publish`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      apiKey,
      notaryHashId: attestation.notaryHashId,
      attestation: {
        header: attestation.header,
        certificate: attestation.certificate,
        countersignatures: attestation.countersignatures ?? [],
      },
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error ?? `publish failed: HTTP ${res.status}`);

  console.log("published");
  console.log(`  ${data.url}`);
  console.log("");
  console.log("Your event log stayed on this machine — only the signed header,");
  console.log("certificate and countersignatures were sent.");
}

async function doVerify(target, argv = []) {
  if (!target) throw new Error("usage: verify <session-id|path-to-attestation.json> [--no-refresh]");
  const file = resolveAttestationPath(target);
  let attestation = JSON.parse(fs.readFileSync(file, "utf8"));

  // An attestation verified soon after anchoring still holds a mempool-era
  // certificate. Top it up first, so `onChain` has something to check —
  // unless the caller is deliberately verifying the bytes as they stand.
  const anchored = attestation.certificate?.anchor?.txid;
  const unconfirmed = anchored && attestation.certificate?.anchor?.blockHeight == null;
  if (unconfirmed && !argv.includes("--no-refresh")) {
    const r = await refreshCertificate(attestation, loadConfig());
    if (r.ok && r.confirmed) {
      attestation.certificate = r.certificate;
      attestation.anchorStatus = "confirmed";
      fs.writeFileSync(file, JSON.stringify(attestation, null, 2));
      console.log("(refreshed: anchor has since confirmed)\n");
    }
  }

  const report = await verifyAttestation(attestation, { strict: false, checkChain: true });

  console.log(report.ok ? "VERIFIED" : "NOT VERIFIED");
  if (report.evidence) {
    const e = report.evidence;
    console.log(`Evidence level ${e.level} — ${e.name}`);
    console.log(`  ${e.summary}`);
  }
  console.log("");
  for (const [name, value] of Object.entries(report.checks)) {
    const mark = value === true ? "pass" : value === false ? "FAIL" : "skip";
    console.log(`  ${mark.padEnd(5)} ${name}`);
  }
  if (report.reasons.length) {
    console.log("\nreasons");
    for (const r of report.reasons) console.log(`  - ${r}`);
  }

  if (report.profile) {
    const d = report.derived ?? derive(report.profile);
    const p = report.profile;
    console.log("\ncollaboration profile");
    console.log(`  human turns         ${p.humanTurns}`);
    console.log(`  assistant turns     ${p.assistantTurns}`);
    console.log(`  tool calls          ${p.toolCalls}`);
    console.log(`  revision cycles     ${p.revisionCycles} (${pct(d.revisionRatio)} of human turns)`);
    console.log(`  unattended inputs   ${p.unattendedTurns}${p.unattendedTurns ? ` (max run ${p.maxConsecutiveUnattended})` : ""}`);
    console.log(`  delegated turns     ${p.delegatedTurns}`);
    console.log(`  human input         ${p.humanInputChars} chars`);
    console.log(`  model output        ${p.assistantOutputChars} chars`);
    console.log(`  active time         ${d.activeMinutes} min of ${Math.round(p.spanSeconds / 60)} min elapsed`);
    console.log(`  prompt sources      ${JSON.stringify(p.promptSources)}`);
    if (d.fullyUnattended) {
      console.log("\n  NOTE: no human-originated input in this session.");
    }
  }

  if (report.anchor?.present) {
    console.log("\nanchor");
    console.log(`  network  ${report.anchor.network}`);
    console.log(`  txid     ${report.anchor.txid ?? "(not yet broadcast)"}`);
    console.log(`  height   ${report.anchor.blockHeight ?? "(unconfirmed)"}`);
  }

  const e = report.evidence;
  if (e?.nextLevelRequires) {
    console.log(`\nto reach level ${e.level + 1}: ${e.nextLevelRequires}`);
  }
  if (e?.caveat) console.log(`\n${e.caveat}`);

  process.exit(report.ok ? 0 : 1);
}

function pct(x) {
  return `${Math.round((x ?? 0) * 100)}%`;
}

/**
 * Emit C2PA assertions for an attestation.
 *
 * Default output is the gathered-assertion bundle, because that is the path
 * that needs no certificate: another party signs the manifest and includes our
 * evidence alongside their own claims. `--manifest` emits a full c2patool
 * definition for when we hold an X.509 certificate of our own.
 */
async function doC2pa(args) {
  const target = args.find((a) => !a.startsWith("--"));
  if (!target) throw new Error("usage: c2pa <session-id|path> [--manifest] [--out FILE]");

  const flag = (name) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : undefined;
  };

  const file = fs.existsSync(target) ? target : path.join(sessionDir(target), "attestation.json");
  if (!fs.existsSync(file)) throw new Error(`no attestation found at ${file}`);
  const attestation = JSON.parse(fs.readFileSync(file, "utf8"));

  const opts = {
    title: flag("title"),
    format: flag("format"),
    verifyBase: flag("verify-base"),
    taUrl: flag("ta-url"),
  };

  const output = args.includes("--manifest")
    ? buildManifestDefinition(attestation, opts)
    : buildGatheredAssertions(attestation, opts);

  const json = JSON.stringify(output, null, 2);
  const out = flag("out");
  if (out) {
    fs.writeFileSync(out, json);
    const rec = recommendDigitalSourceType(attestation.header.profile);
    console.log(`wrote ${out}`);
    console.log(`  digitalSourceType  ${rec.term}`);
    console.log(`  rationale          ${rec.rationale}`);
    if (!attestation.certificate?.anchor?.txid) {
      console.log("");
      console.log("note: this attestation has no on-chain anchor yet, so the assertion");
      console.log("      carries no public timestamp. Anchor it before publishing.");
    }
  } else {
    console.log(json);
  }
}
