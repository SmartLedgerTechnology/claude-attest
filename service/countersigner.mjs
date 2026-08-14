#!/usr/bin/env node
/**
 * The ProofOfProcess platform countersigner.
 *
 * A standalone HTTP service that signs a statement saying: "I, this platform,
 * received digest X from a client authenticated as Y at time T." It holds a key
 * no creator controls, which is the entire point — it is what moves an
 * attestation from Level 1 (Self Attested) to Level 2 (Platform Observed).
 *
 * Deliberate limits, encoded rather than assumed:
 *
 *   - It signs `observed: "submission"`, never `"capture"`. This service sees a
 *     digest arrive; it does not watch anyone work. A client could still submit
 *     the digest of a fabricated session. What a submission countersignature
 *     defeats is BACKDATING and REPUDIATION, and it binds the record to an
 *     authenticated account. Claiming more would be false.
 *
 *   - It never sees content. Only a 32-byte digest crosses the wire, so running
 *     this service creates no confidentiality obligation over anyone's work.
 *
 *   - It signs whatever digest it is given. It cannot and does not validate the
 *     underlying session, and the statement says so in its own fields.
 *
 * Zero dependencies beyond the signing suite. Run it behind TLS.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  buildStatement,
  statementDigest,
  OBSERVED,
  ROLES,
} from "../packages/proof-of-process/src/countersign.mjs";
import { KeyStore } from "./keystore.mjs";

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "0.0.0.0";
const SIGNER = process.env.COUNTERSIGNER_NAME ?? "proofofprocess.ai";
const KEY_FILE = process.env.COUNTERSIGNER_KEY ?? "/data/countersigner.json";
const ALGORITHM = process.env.COUNTERSIGNER_ALGORITHM ?? "ML-DSA-65";
const MAX_BODY = 8 * 1024;

const apiKeys = new Set(
  (process.env.COUNTERSIGNER_API_KEYS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

const store = await connectStore();
const key = await loadOrCreateKey();
console.error(`countersigner: ${ALGORITHM} keyId=${key.keyId} signer=${SIGNER}`);
if (apiKeys.size === 0) {
  console.error("countersigner: WARNING — COUNTERSIGNER_API_KEYS is empty, all requests accepted");
}

http
  .createServer(handle)
  .listen(PORT, HOST, () => console.error(`countersigner listening on ${HOST}:${PORT}`));

async function handle(req, res) {
  try {
    if (req.method === "GET" && req.url === "/healthz") {
      return json(res, 200, { status: "ok", signer: SIGNER, algorithm: ALGORITHM, keyId: key.keyId });
    }
    // The public key is published so anyone can verify without contacting us.
    if (req.method === "GET" && req.url === "/v1/pubkey") {
      return json(res, 200, {
        signer: SIGNER,
        algorithm: ALGORITHM,
        publicKey: key.publicKey,
        keyId: key.keyId,
        encoding: "base64",
      });
    }
    if (req.method === "POST" && req.url === "/v1/countersign") {
      return await countersign(req, res);
    }
    return json(res, 404, { error: "not found" });
  } catch (e) {
    console.error(`countersigner error: ${e?.stack ?? e}`);
    return json(res, 500, { error: "internal error" });
  }
}

async function countersign(req, res) {
  const provided = req.headers["x-api-key"];
  const auth = await authorizeKey(provided);
  if (!auth.ok) return json(res, 401, { error: auth.reason });

  let body;
  try {
    body = JSON.parse(await readBody(req));
  } catch (e) {
    return json(res, 400, { error: `invalid JSON body: ${e.message}` });
  }

  const subject = body?.subject;
  if (typeof subject !== "string" || !/^[0-9a-f]{64}$/i.test(subject)) {
    return json(res, 400, { error: "subject must be a 64-character hex sha256 digest" });
  }

  // The client is identified by a stable fingerprint of its API key, never the
  // key itself — the statement is published inside certificates, and a
  // credential must not travel with them.
  const clientKeyId = typeof provided === "string" ? fingerprint(provided) : null;

  const statement = buildStatement({
    role: ROLES.PLATFORM,
    signer: SIGNER,
    observed: OBSERVED.SUBMISSION,
    observedAt: new Date().toISOString(),
    subject: subject.toLowerCase(),
    clientKeyId,
  });

  const signature = await sign(statementDigest(statement));

  return json(res, 200, {
    countersignature: {
      ...statement,
      algorithm: ALGORITHM,
      publicKey: key.publicKey,
      keyId: key.keyId,
      signature,
      encoding: "base64",
    },
  });
}

/* ---------- key management ---------- */

async function loadOrCreateKey() {
  if (fs.existsSync(KEY_FILE)) {
    const k = JSON.parse(fs.readFileSync(KEY_FILE, "utf8"));
    if (k.algorithm !== ALGORITHM) {
      throw new Error(`key at ${KEY_FILE} is ${k.algorithm}, but COUNTERSIGNER_ALGORITHM=${ALGORITHM}`);
    }
    return k;
  }
  const dir = path.dirname(KEY_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const seed = randomBytes(32);
  const impl = await mlDsa();
  const publicKey = Buffer.from(impl.keygen(seed).publicKey).toString("base64");
  const k = {
    algorithm: ALGORITHM,
    createdAt: new Date().toISOString(),
    privateKey: seed.toString("base64"),
    publicKey,
    keyId: fingerprint(publicKey),
  };
  fs.writeFileSync(KEY_FILE, JSON.stringify(k, null, 2), { mode: 0o600 });
  console.error(`countersigner: generated new key at ${KEY_FILE} — BACK THIS UP`);
  return k;
}

async function sign(digestHex) {
  const impl = await mlDsa();
  const keys = impl.keygen(Buffer.from(key.privateKey, "base64"));
  const sig = impl.sign(keys.secretKey, Buffer.from(digestHex, "hex"));
  return Buffer.from(sig).toString("base64");
}

async function mlDsa() {
  const mod = await import("@noble/post-quantum/ml-dsa");
  const impl = { "ML-DSA-44": mod.ml_dsa44, "ML-DSA-65": mod.ml_dsa65, "ML-DSA-87": mod.ml_dsa87 }[
    ALGORITHM
  ];
  if (!impl) throw new Error(`unsupported COUNTERSIGNER_ALGORITHM: ${ALGORITHM}`);
  return impl;
}

/**
 * Connect to the shared subscription key store. Optional by design: without
 * REDIS_URL the countersigner keeps working from environment keys alone, which
 * is what it did before billing existed.
 */
async function connectStore() {
  const url = process.env.REDIS_URL;
  if (!url) return null;
  try {
    const { createClient } = await import("redis");
    const client = createClient({ url });
    client.on("error", (e) => console.error(`countersigner redis: ${e.message}`));
    await client.connect();
    console.error("countersigner: subscription key store connected");
    return new KeyStore(client);
  } catch (e) {
    console.error(`countersigner: key store unavailable (${e.message}) — env keys only`);
    return null;
  }
}

/* ---------- helpers ---------- */

/**
 * Authorize a request. Two sources, checked in order:
 *
 *   1. COUNTERSIGNER_API_KEYS from the environment — operational keys, and
 *      anyone provisioned before billing existed.
 *   2. The subscription key store shared with the billing service, which
 *      carries expiry, so a lapsed subscription stops working without anyone
 *      editing a config file.
 *
 * The env path is kept deliberately: introducing the store must not invalidate
 * keys that already work today.
 */
async function authorizeKey(provided) {
  if (typeof provided !== "string" || provided === "") {
    // Preserve the previous behaviour of running open when nothing is configured.
    if (apiKeys.size === 0 && !store) return { ok: true, via: "open" };
    return { ok: false, reason: "invalid or missing API key" };
  }
  if (accepts(provided)) return { ok: true, via: "env" };

  if (store) {
    try {
      const r = await store.authorize(provided);
      if (r.ok) return { ok: true, via: "subscription", tier: r.record?.tier };
      // Distinguish "wrong key" from "you stopped paying" — the customer can
      // act on the second one.
      if (r.reason === "expired" || r.reason === "revoked") {
        return { ok: false, reason: `subscription ${r.reason}` };
      }
    } catch (e) {
      console.error(`countersigner: key store unavailable (${e.message})`);
    }
  }
  if (apiKeys.size === 0 && !store) return { ok: true, via: "open" };
  return { ok: false, reason: "invalid or missing API key" };
}

/** Constant-time membership test, so key comparison cannot be timed. */
function accepts(provided) {
  if (typeof provided !== "string") return false;
  const given = Buffer.from(provided);
  let ok = false;
  for (const k of apiKeys) {
    const known = Buffer.from(k);
    if (known.length === given.length && timingSafeEqual(known, given)) ok = true;
  }
  return ok;
}

function fingerprint(s) {
  return createHash("sha256").update(s).digest("base64url").slice(0, 16);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function json(res, code, obj) {
  const b = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(b) });
  res.end(b);
}
