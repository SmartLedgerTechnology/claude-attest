import test from "node:test";
import assert from "node:assert/strict";
import { makeMailer, confirmationMail, DEFAULT_FROM } from "../service/mailer.mjs";

const quiet = { log: () => {} };

test("without SMTP settings the mailer is null, not a broken object", () => {
  // Callers must handle "mail is unavailable" explicitly rather than discover it
  // when a send throws — this is how the service runs in development.
  assert.equal(makeMailer({}, quiet), null);
  assert.equal(makeMailer({ SMTP_HOST: "h" }, quiet), null, "a host alone is not enough");
  assert.equal(makeMailer({ SMTP_HOST: "h", SMTP_USER: "u" }, quiet), null, "credentials are required");
});

test("with full settings a mailer is returned", () => {
  const m = makeMailer({ SMTP_HOST: "h", SMTP_USER: "u", SMTP_PASS: "p" }, quiet);
  assert.ok(m);
  assert.equal(m.from, DEFAULT_FROM);
  m.close();
});

test("the From address can be overridden without touching code", () => {
  const m = makeMailer({ SMTP_HOST: "h", SMTP_USER: "u", SMTP_PASS: "p", MAIL_FROM: "A <a@b.com>" }, quiet);
  assert.equal(m.from, "A <a@b.com>");
  m.close();
});

test("the confirmation carries the link and nothing that could track a reader", () => {
  const url = "https://proofofprocess.ai/confirm?t=abc123";
  const mail = confirmationMail({ confirmUrl: url, source: "landing" });

  assert.ok(mail.text.includes(url), "the link must be present verbatim, not shortened or wrapped");
  assert.match(mail.subject, /confirm/i);
  // The page promises no tracking pixels. Plain text is how that promise is kept.
  assert.doesNotMatch(mail.text, /<img|<html|<a\s|1x1|\.gif/i);
});

test("the confirmation tells an uninterested recipient that doing nothing is enough", () => {
  const mail = confirmationMail({ confirmUrl: "https://x/confirm?t=1", source: "landing" });
  // Someone else can type your address into any form. The mail has to make clear
  // that ignoring it costs nothing and leaves no account behind.
  assert.match(mail.text, /ignore/i);
  assert.match(mail.text, /no account/i);
  assert.match(mail.text, /deleted within a week/i);
});

test("the confirmation says where the request came from", () => {
  assert.match(confirmationMail({ confirmUrl: "u", source: "post" }).text, /launch write-up/i);
  assert.match(confirmationMail({ confirmUrl: "u", source: "landing" }).text, /from the website/i);
});

/* ------------------------- operational notifications ----------------------- */

import { events } from "../service/notify.mjs";

test("a notification never renders a missing field as 'undefined'", () => {
  // This shipped once: confirm() did not return the source, so the Telegram
  // alert read "from: undefined". Formatters must survive a partial record.
  for (const r of [{}, { total: 3 }, { source: "post" }, { source: undefined, total: undefined }]) {
    const msg = events.waitlist(r);
    assert.doesNotMatch(msg, /undefined|null|NaN/, `bad render for ${JSON.stringify(r)}: ${msg}`);
  }
});

test("a complete waitlist notification says where and how many, but never who", () => {
  const msg = events.waitlist({ source: "landing", total: 7, email: "greg@example.com" });
  assert.match(msg, /landing/);
  assert.match(msg, /7/);
  // The address stays in Redis. Telegram is a third party.
  assert.doesNotMatch(msg, /greg@example\.com/);
});
