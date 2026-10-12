# syntax=docker/dockerfile:1

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
# Set by CI from package.json (see scripts/release.js). Empty means "use package.json".
ARG VERSION=""
ARG REVISION=""

LABEL org.opencontainers.image.title="Certificate Workbench" \
      org.opencontainers.image.description="Validate, decode, convert and create X.509 certificates, keys and CSRs" \
      org.opencontainers.image.source="https://github.com/sunnykatiyar50/Certificate-Workbench" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV NODE_ENV=production \
    PORT=33003 \
    APP_VERSION=${VERSION}

WORKDIR /app
COPY --from=deps /app/node_modules node_modules
COPY package.json server.js CHANGELOG.md ./
COPY lib lib
COPY trust-data trust-data
COPY public public
COPY scripts/hash-password.js scripts/hash-password.js

# The history database lives here; mount a volume to keep it across container restarts.
RUN mkdir -p /app/data && chown node:node /app/data
ENV DATA_DIR=/app/data
VOLUME ["/app/data"]

USER node
EXPOSE 33003

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
