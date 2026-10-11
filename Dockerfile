# syntax=docker/dockerfile:1

FROM node:22-alpine AS deps
WORKDIR /app/backend
COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
# Set by CI from backend/package.json (see scripts/release.js). Empty means "use package.json".
ARG VERSION=""
ARG REVISION=""

LABEL org.opencontainers.image.title="Certificate Validator" \
      org.opencontainers.image.description="Validate X.509 certificates, certificate chains and live TLS sites" \
      org.opencontainers.image.source="https://github.com/sunnykatiyar50/Certificate-Validator" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV NODE_ENV=production \
    PORT=3003 \
    APP_VERSION=${VERSION}

# server.js serves ../public, so keep the backend/ + public/ layout.
WORKDIR /app
COPY --from=deps /app/backend/node_modules backend/node_modules
COPY backend/package.json backend/server.js backend/
COPY backend/lib backend/lib
COPY public public

WORKDIR /app/backend
USER node
EXPOSE 3003

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
