/**
 * Outbound mail.
 *
 * One dependency, and it was chosen carefully. This image also runs the
 * countersigner, which holds the key every Level 2 claim rests on, so the
 * Dockerfile argues for keeping it small. Nodemailer earns its place by having
 * zero runtime dependencies of its own and by getting the parts that are easy
 * to get subtly wrong — header folding, transfer encoding, dot-stuffing, CRLF
 * normalization — right for mail that goes to strangers.
 *
 * Two rules about what we send:
 *
 *   PLAIN TEXT ONLY.  The page promises no tracking pixels. The simplest way to
 *     keep that promise is to have no HTML part at all, so there is nothing to
 *     embed a pixel in and nothing to rewrite links into.
 *
 *   EVERY MESSAGE CAN BE STOPPED.  List-Unsubscribe (with one-click) on every
 *     send, not just the ones a regulator would insist on.
 *
 * Sending is NOT best-effort, unlike the Telegram notifier. If a confirmation
 * mail fails, the person is left waiting for something that will never arrive,
 * so the caller is told and can say so.
 */

import nodemailer from "nodemailer";

export const DEFAULT_FROM = "ProofOfProcess.ai <support@proofofprocess.ai>";

/**
 * @returns a mailer, or null when SMTP is not configured. A null mailer is a
 *   legitimate state — it is how the service runs in development and how it ran
 *   before the domain could send at all — so callers must handle it rather than
 *   assume mail is available.
 */
export function makeMailer(env = process.env, { log = console.error } = {}) {
  const host = env.SMTP_HOST;
  const user = env.SMTP_USER;
  const pass = env.SMTP_PASS;
  if (!host || !user || !pass) {
    log("mail: SMTP not configured — outbound mail disabled");
    return null;
  }

  const port = Number(env.SMTP_PORT ?? 465);
  const transport = nodemailer.createTransport({
    host,
    port,
    // 465 is implicit TLS. Anything else negotiates STARTTLS, and `requireTLS`
    // makes that mandatory rather than a downgrade a network can strip.
    secure: port === 465,
    requireTLS: port !== 465,
    auth: { user, pass },
    // This is a mailbox at a shared host, not a bulk sending platform. One
    // connection, a couple of messages a second, so a burst of signups cannot
    // get the account throttled or suspended.
    pool: true,
    maxConnections: 1,
    maxMessages: 50,
    rateDelta: 1000,
    rateLimit: 2,
  });

  const from = env.MAIL_FROM ?? DEFAULT_FROM;
  const replyTo = env.MAIL_REPLY_TO ?? undefined;

  return {
    from,
    /** Verify credentials and TLS without sending anything. */
    verify: () => transport.verify(),

    /**
     * @param unsubscribeUrl  when given, added as List-Unsubscribe. Mail clients
     *   surface it as a native "unsubscribe" control, which is a far better
     *   outcome for everyone than the recipient reaching for "report spam".
     */
    async send({ to, subject, text, unsubscribeUrl }) {
      const headers = {};
      if (unsubscribeUrl) {
        headers["List-Unsubscribe"] = `<${unsubscribeUrl}>`;
        headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click";
      }
      const info = await transport.sendMail({ from, to, replyTo, subject, text, headers });
      return { messageId: info.messageId, accepted: info.accepted ?? [] };
    },

    close: () => transport.close(),
  };
}

/* --------------------------------- messages -------------------------------- */

/**
 * Confirmation. Deliberately short, and it says who asked and from where, so a
 * person who did not sign up can tell at a glance that ignoring it is enough —
 * no account was created and nothing happens if they do nothing.
 */
export function confirmationMail({ confirmUrl, source }) {
  return {
    subject: "Confirm your email — ProofOfProcess.ai",
    text: [
      "Someone asked to be kept posted about ProofOfProcess.ai using this address",
      `${source === "post" ? "from the launch write-up" : "from the website"}.`,
      "",
      "If that was you, confirm here:",
      confirmUrl,
      "",
      "If it wasn't, ignore this. Nothing was created, no account exists, and you",
      "will not hear from us again — an unconfirmed address is deleted within a week.",
      "",
      "What you're signing up for: one email, when there is something worth reading.",
      "No drip sequence, no tracking pixels, never shared or sold.",
      "",
      "— ProofOfProcess.ai",
      "  https://proofofprocess.ai",
    ].join("\n"),
  };
}
