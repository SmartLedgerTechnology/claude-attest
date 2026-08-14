import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * State lives in CLAUDE_ATTEST_HOME (default ~/.claude-attest), never in the
 * plugin directory: ${CLAUDE_PLUGIN_ROOT} is replaced wholesale on every plugin
 * update, and evidence that disappears when you run `/plugin update` is not
 * evidence.
 */
export function home() {
  return process.env.CLAUDE_ATTEST_HOME || path.join(os.homedir(), ".claude-attest");
}

export function ensureDir(dir, mode = 0o700) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode });
  return dir;
}

export function sessionDir(sessionId) {
  return ensureDir(path.join(home(), "sessions", sessionId));
}

export function keysDir() {
  return ensureDir(path.join(home(), "keys"));
}

export function debugLog(message) {
  // Hooks must never write to stderr on a normal run — Claude Code surfaces it
  // to the user or the model. Diagnostics go to a file instead.
  if (!process.env.CLAUDE_ATTEST_DEBUG) return;
  try {
    fs.appendFileSync(
      path.join(ensureDir(home()), "debug.log"),
      `${new Date().toISOString()} ${message}\n`
    );
  } catch {
    // A failing debug log must not take down the hook.
  }
}

const DEFAULTS = {
  anchor: "mock",
  notaryhashUrl: "https://notaryhash.com",
  algorithm: "ML-DSA-65",
  batch: true,
  captureContent: false,
  countersignerUrl: null,
};

/**
 * Config resolution: defaults < config.json < environment. Environment wins so
 * CI and one-off runs can override without editing a file.
 */
export function loadConfig() {
  let file = {};
  const p = path.join(home(), "config.json");
  try {
    if (fs.existsSync(p)) file = JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    debugLog(`config parse failed: ${e.message}`);
  }
  const env = {
    anchor: process.env.CLAUDE_ATTEST_ANCHOR,
    notaryhashUrl: process.env.NOTARYHASH_URL,
    apiKey: process.env.NOTARYHASH_API_KEY,
    algorithm: process.env.CLAUDE_ATTEST_ALGORITHM,
    batch: parseBool(process.env.CLAUDE_ATTEST_BATCH),
    captureContent: parseBool(process.env.CLAUDE_ATTEST_CAPTURE_CONTENT),
    countersignerUrl: process.env.COUNTERSIGNER_URL,
    countersignerApiKey: process.env.COUNTERSIGNER_API_KEY,
  };
  const merged = { ...DEFAULTS, ...file };
  for (const [k, v] of Object.entries(env)) if (v !== undefined) merged[k] = v;
  return merged;
}

function parseBool(v) {
  if (v === undefined) return undefined;
  return v === "1" || v === "true" || v === "yes";
}
