# Countersigner image.
#
# Deliberately minimal: the service is ~200 lines with one dependency, and it
# holds the key that every Level 2 claim rests on. The less that is in this
# image, the less there is to audit.
FROM node:22-alpine

WORKDIR /app

# Only the dependency manifest first, so a code change does not re-resolve deps.
COPY deploy/package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund

# The service and the shared protocol module it imports. Layout must match the
# repo, because countersigner.mjs resolves ../packages/... relatively.
COPY service/ ./service/
COPY packages/proof-of-process/src/ ./packages/proof-of-process/src/

# The key lives on a mounted volume, never in the image.
ENV COUNTERSIGNER_KEY=/data/countersigner.json \
    PORT=8787 \
    HOST=0.0.0.0
RUN mkdir -p /data && chown -R node:node /data /app

USER node
EXPOSE 8787

# Uses ${PORT} rather than a literal: this image runs both the countersigner
# (8787) and the billing service (8788), and a hardcoded port makes one of them
# permanently report unhealthy while serving traffic perfectly well.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1 || exit 1

CMD ["node", "service/countersigner.mjs"]
