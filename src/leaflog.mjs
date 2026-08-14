import fs from "node:fs";
import path from "node:path";
import { hashLeaf, hashPayload } from "../packages/proof-of-process/src/canonical.mjs";
import { ZERO_HASH } from "../packages/proof-of-process/src/index.mjs";
import { debugLog } from "./paths.mjs";

const LOCK_STALE_MS = 5000;
const LOCK_RETRIES = 200;
const LOCK_WAIT_MS = 5;

/**
 * Append-only NDJSON leaf log, one directory per session.
 *
 *   leaves.ndjson  one leaf per line, in commit order
 *   head.json      {seq, prevLeafHash, lastAttestedUuid, attestedLineCount}
 *
 * The head file is what keeps appends O(1): reading the tail of a multi-megabyte
 * NDJSON file on every tool call would make the hook the slowest thing in the
 * session.
 *
 * Only the leaf's payload HASH is stored by default. The log is therefore safe
 * to sync, back up, or hand to a third party without disclosing prompts, code,
 * or tool output.
 */

export function readHead(dir) {
  const p = path.join(dir, "head.json");
  try {
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    debugLog(`head.json unreadable, restarting chain: ${e.message}`);
  }
  return { seq: 0, prevLeafHash: ZERO_HASH, lastAttestedUuid: null, attestedLineCount: 0 };
}

function writeHead(dir, head) {
  const p = path.join(dir, "head.json");
  const tmp = `${p}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(head));
  fs.renameSync(tmp, p); // atomic: a torn head file would break the whole chain
}

/**
 * Append one leaf. Returns the leaf, or null if the append failed — callers are
 * hooks, and a hook that throws is a hook that interrupts someone's work.
 */
export function appendLeaf(dir, kind, payload, extra = {}) {
  try {
    return withLock(dir, () => {
      const head = readHead(dir);
      const leaf = {
        v: 1,
        seq: head.seq,
        ts: new Date().toISOString(),
        kind,
        payloadHash: hashPayload(payload),
        prev: head.prevLeafHash,
        ...extra,
      };
      fs.appendFileSync(path.join(dir, "leaves.ndjson"), JSON.stringify(leaf) + "\n");
      writeHead(dir, {
        ...head,
        seq: head.seq + 1,
        prevLeafHash: hashLeaf(leaf),
      });
      return leaf;
    });
  } catch (e) {
    debugLog(`appendLeaf(${kind}) failed: ${e.stack ?? e}`);
    return null;
  }
}

/** Append several leaves under one lock. Used by the Stop checkpoint. */
export function appendLeaves(dir, entries) {
  try {
    return withLock(dir, () => {
      const head = readHead(dir);
      let seq = head.seq;
      let prev = head.prevLeafHash;
      const out = [];
      const lines = [];
      for (const { kind, payload, extra } of entries) {
        const leaf = {
          v: 1,
          seq: seq++,
          ts: new Date().toISOString(),
          kind,
          payloadHash: hashPayload(payload),
          prev,
          ...(extra ?? {}),
        };
        prev = hashLeaf(leaf);
        out.push(leaf);
        lines.push(JSON.stringify(leaf));
      }
      if (lines.length) fs.appendFileSync(path.join(dir, "leaves.ndjson"), lines.join("\n") + "\n");
      writeHead(dir, { ...head, seq, prevLeafHash: prev });
      return out;
    });
  } catch (e) {
    debugLog(`appendLeaves failed: ${e.stack ?? e}`);
    return [];
  }
}

/** Record where the transcript walk got to, so the next checkpoint resumes there. */
export function updateTranscriptCursor(dir, lastAttestedUuid, attestedLineCount) {
  try {
    withLock(dir, () => {
      writeHead(dir, { ...readHead(dir), lastAttestedUuid, attestedLineCount });
    });
  } catch (e) {
    debugLog(`updateTranscriptCursor failed: ${e.message}`);
  }
}

export function readLeaves(dir) {
  const p = path.join(dir, "leaves.ndjson");
  if (!fs.existsSync(p)) return [];
  return fs
    .readFileSync(p, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/**
 * mkdir is atomic on every platform we care about, which makes it a usable
 * mutex without a dependency. Parallel tool calls mean several PostToolUse
 * hooks can land at once, and an unsynchronized `prev` would corrupt the chain.
 *
 * If the lock cannot be taken we proceed ANYWAY rather than block: a slightly
 * out-of-order leaf is a recoverable annoyance, a hung hook is not.
 */
function withLock(dir, fn) {
  const lock = path.join(dir, ".lock");
  for (let i = 0; i < LOCK_RETRIES; i++) {
    try {
      fs.mkdirSync(lock);
      try {
        return fn();
      } finally {
        try {
          fs.rmdirSync(lock);
        } catch {
          // Losing the lock dir is not fatal; the next holder will break it as stale.
        }
      }
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      breakStaleLock(lock);
      sleepSync(LOCK_WAIT_MS);
    }
  }
  debugLog("lock timeout, proceeding unlocked");
  return fn();
}

function breakStaleLock(lock) {
  try {
    if (Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS) fs.rmdirSync(lock);
  } catch {
    // Race with the legitimate holder releasing it — nothing to do.
  }
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}
