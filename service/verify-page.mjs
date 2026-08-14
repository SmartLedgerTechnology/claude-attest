import { derive } from "../packages/proof-of-process/src/profile.mjs";

/**
 * Server-rendered verification page.
 *
 * Rendered on the server rather than fetched by script, because this is the page
 * a publisher, examiner, or court opens from a link. It must work with scripts
 * disabled, be readable by a crawler, and not depend on our API staying up in
 * the reader's browser.
 *
 * Every claim on the page is either recomputed here or explicitly marked as
 * not-checked. Nothing is asserted on the creator's say-so.
 */

const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const CHECK_LABELS = {
  format: "Format is a recognized version",
  leafContinuity: "Event log is unbroken",
  hashChain: "Event chain is intact",
  merkleRoot: "Event tree matches the signed root",
  anchorBinding: "The anchored digest is this record",
  signature: "Signature verifies",
  transcriptChain: "No turns were omitted or rewritten",
  onChain: "Confirmed on the public chain",
};

export function renderVerifyPage({ id, report, header, certificate, publishedAt, notFound }) {
  if (notFound) return page("Not found", `<div class="card bad"><h1>No record here</h1>
    <p class="sub">Nothing has been published under <code>${esc(id)}</code>. Check the link, or ask whoever shared it to publish the record.</p></div>`);

  const ok = report.ok;
  const ev = report.evidence ?? {};
  const p = report.profile;
  const d = p ? derive(p) : null;
  const anchor = report.anchor ?? {};

  const checks = Object.entries(report.checks)
    .map(([k, v]) => {
      const state = v === true ? "pass" : v === false ? "fail" : "skip";
      const mark = v === true ? "✓" : v === false ? "✕" : "–";
      const why = { leafContinuity: "not disclosed", hashChain: "not disclosed", merkleRoot: "not disclosed" };
      const note = v === null ? ` <span class="note">${esc(why[k] ?? "not checked")}</span>` : "";
      return `<li class="${state}"><span class="mark">${mark}</span>${esc(CHECK_LABELS[k] ?? k)}${note}</li>`;
    })
    .join("");

  const reasons = report.reasons?.length
    ? `<div class="card bad"><h2>Why it did not verify</h2><ul class="plain">${report.reasons
        .map((r) => `<li>${esc(r)}</li>`)
        .join("")}</ul></div>`
    : "";

  const explorer = anchor.txid ? `https://whatsonchain.com/tx/${esc(anchor.txid)}` : null;

  const profileBlock = p
    ? `<div class="card">
      <h2>How this work was produced</h2>
      <p class="sub">These figures are inside the signed record. They cannot be adjusted after the fact without breaking verification.</p>
      <div class="grid">
        ${stat("Human turns", p.humanTurns)}
        ${stat("Model turns", p.assistantTurns)}
        ${stat("Tool calls", p.toolCalls)}
        ${stat("Revision cycles", `${p.revisionCycles}`, `${Math.round((d.revisionRatio ?? 0) * 100)}% of human turns`)}
        ${stat("Unattended inputs", p.unattendedTurns, p.unattendedTurns ? `longest run ${p.maxConsecutiveUnattended}` : "none")}
        ${stat("Active time", `${d.activeMinutes} min`, `over ${Math.round((p.spanSeconds ?? 0) / 3600)} h elapsed`)}
        ${stat("Human input", `${p.humanInputChars.toLocaleString()}`, "characters typed")}
        ${stat("Model output", `${p.assistantOutputChars.toLocaleString()}`, "characters generated")}
      </div>
      ${
        d.fullyUnattended
          ? `<p class="flag">No human-originated input was recorded in this session.</p>`
          : ""
      }
    </div>`
    : "";

  return page(
    ok ? "Verified" : "Not verified",
    `
    <div class="verdict ${ok ? "good" : "bad"}">
      <div class="big">${ok ? "Verified" : "Not verified"}</div>
      <div class="lvl">${esc(ev.name ?? "")}</div>
      <p class="sub">${esc(ev.summary ?? "")}</p>
    </div>

    ${reasons}

    <div class="card">
      <h2>What was checked</h2>
      <ul class="checks">${checks}</ul>
    </div>

    ${profileBlock}

    <div class="card">
      <h2>Anchor</h2>
      ${
        anchor.present && anchor.txid
          ? `<dl>
              <dt>Network</dt><dd>${esc(anchor.network)}</dd>
              <dt>Block</dt><dd>${anchor.blockHeight ? esc(anchor.blockHeight) : "awaiting confirmation"}</dd>
              <dt>Timestamped</dt><dd>${anchor.blockTime ? esc(new Date(anchor.blockTime * 1000).toUTCString()) : "—"}</dd>
              <dt>Transaction</dt><dd><a href="${explorer}" rel="noopener noreferrer">${esc(anchor.txid)}</a></dd>
            </dl>
            <p class="sub">Anyone can confirm this independently against Bitcoin block headers — no trust in ProofOfProcess required.</p>`
          : `<p class="sub">This record has not been anchored to a public chain.</p>`
      }
    </div>

    <div class="card">
      <h2>What this does and does not establish</h2>
      <div class="two">
        <div>
          <h3 class="yes">Established</h3>
          <ul class="plain">
            <li>A record with exactly this content existed at the block time above.</li>
            <li>It has not been altered since.</li>
            <li>The figures above are bound into the signature.</li>
          </ul>
        </div>
        <div>
          <h3 class="no">Not established</h3>
          <ul class="plain">
            <li>Authorship. ${esc(
              ev.level >= 2
                ? "The capture platform countersigned this, but the creator holds their own key."
                : "The signing key is held by the creator, so this is a self-attestation."
            )}</li>
            <li>That any particular file came from this session.</li>
          </ul>
        </div>
      </div>
    </div>

    <div class="meta">
      <div><span>Record</span><code>${esc(id)}</code></div>
      <div><span>Session</span><code>${esc(header?.sessionId ?? "—")}</code></div>
      <div><span>Captured by</span><code>${esc(header?.capture?.adapter ?? "—")} ${esc(header?.capture?.adapterVersion ?? "")}</code></div>
      <div><span>Signing key</span><code>${esc(header?.publicKeyId ?? "—")} · ${esc(header?.algorithm ?? "")}</code></div>
      ${publishedAt ? `<div><span>Published</span><code>${esc(new Date(publishedAt).toUTCString())}</code></div>` : ""}
    </div>
    `
  );
}

function stat(label, value, sub) {
  return `<div class="stat"><div class="v">${esc(value)}</div><div class="l">${esc(label)}</div>${
    sub ? `<div class="s">${esc(sub)}</div>` : ""
  }</div>`;
}

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${esc(title)} — ProofOfProcess.ai</title>
<style>
  :root{--bg:#07111f;--panel:rgba(255,255,255,.055);--line:rgba(255,255,255,.11);--text:#f4f8fb;
    --muted:#9fb0c4;--cyan:#65e6ff;--green:#7ef0bf;--red:#ff8f8f;--amber:#ffd479;
    --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
  *{box-sizing:border-box}
  body{margin:0;color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
    background:radial-gradient(circle at 20% 8%,rgba(95,140,255,.16),transparent 34%),
      radial-gradient(circle at 85% 12%,rgba(167,121,255,.12),transparent 30%),
      linear-gradient(180deg,var(--bg),#06101a 55%,#08131f);min-height:100vh;
    display:flex;justify-content:center;padding:5vh 20px 12vh;line-height:1.6}
  .wrap{width:min(760px,100%)}
  .brand{font-weight:800;letter-spacing:-.03em;margin-bottom:2rem}
  .brand span{color:var(--cyan)}
  .verdict{border:1px solid var(--line);border-radius:18px;padding:1.6rem 1.7rem;margin-bottom:1.1rem;background:var(--panel)}
  .verdict.good{border-color:rgba(126,240,191,.4);background:rgba(126,240,191,.08)}
  .verdict.bad{border-color:rgba(255,143,143,.4);background:rgba(255,143,143,.08)}
  .big{font-size:clamp(1.9rem,5vw,2.5rem);font-weight:800;letter-spacing:-.03em;line-height:1.1}
  .verdict.good .big{color:var(--green)} .verdict.bad .big{color:var(--red)}
  .lvl{font-family:var(--mono);font-size:.78rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin-top:.5rem}
  .sub{color:var(--muted);margin:.6rem 0 0;font-size:.95rem}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:1.3rem 1.5rem;margin-bottom:1.1rem}
  .card.bad{border-color:rgba(255,143,143,.35);background:rgba(255,143,143,.07)}
  h1{font-size:1.6rem;margin:0 0 .4rem;letter-spacing:-.02em}
  h2{font-size:1.02rem;margin:0 0 .9rem;letter-spacing:-.01em}
  h3{font-size:.72rem;font-family:var(--mono);letter-spacing:.12em;text-transform:uppercase;margin:0 0 .6rem}
  h3.yes{color:var(--green)} h3.no{color:var(--red)}
  ul.checks{list-style:none;padding:0;margin:0;display:grid;gap:.45rem}
  ul.checks li{display:flex;gap:.7rem;align-items:baseline;font-size:.94rem}
  ul.checks .mark{font-family:var(--mono);width:1rem;flex:none}
  ul.checks li.pass .mark{color:var(--green)} ul.checks li.fail .mark{color:var(--red)}
  ul.checks li.skip{color:var(--muted)} ul.checks li.skip .mark{color:var(--muted)}
  .note{font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-left:.3rem}
  ul.plain{margin:0;padding-left:1.1rem;color:var(--muted);font-size:.92rem}
  ul.plain li{margin-bottom:.4rem}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:var(--line);
    border:1px solid var(--line);border-radius:12px;overflow:hidden;margin-top:.4rem}
  .stat{background:#0a1522;padding:.9rem 1rem}
  .stat .v{font-size:1.45rem;font-weight:700;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
  .stat .l{font-size:.74rem;color:var(--muted);margin-top:.15rem}
  .stat .s{font-size:.7rem;color:var(--muted);opacity:.75;margin-top:.15rem}
  .flag{color:var(--amber);font-size:.9rem;margin:.9rem 0 0}
  dl{display:grid;grid-template-columns:auto 1fr;gap:.45rem 1.2rem;margin:0;font-size:.92rem}
  dt{color:var(--muted)} dd{margin:0;font-family:var(--mono);font-size:.85rem;word-break:break-all}
  a{color:var(--cyan)}
  .two{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1.4rem}
  .meta{display:grid;gap:.5rem;font-size:.8rem;color:var(--muted);margin-top:1.6rem;
    border-top:1px solid var(--line);padding-top:1.2rem}
  .meta div{display:flex;gap:.8rem;flex-wrap:wrap}
  .meta span{min-width:6.5rem}
  code{font-family:var(--mono);font-size:.92em;word-break:break-all}
  footer{margin-top:2rem;font-size:.8rem;color:var(--muted)}
</style></head>
<body><div class="wrap">
  <div class="brand"><a href="/" style="text-decoration:none;color:inherit">ProofOfProcess<span>.ai</span></a></div>
  ${body}
  <footer>Verify this yourself: <code>npx @smartledger.technology/proof-of-process verify &lt;attestation.json&gt;</code></footer>
</div></body></html>`;
}
