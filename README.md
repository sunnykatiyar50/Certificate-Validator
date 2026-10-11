# Certificate Validator

A small web app for validating X.509 certificates and generating key pairs.

**Validate**
- **Upload or paste** a certificate (PEM, CRT, CER, DER, PFX/P12) and see validity, subject/issuer, serial number, fingerprints, key usage, SANs and more.
- **Chain verification:** include intermediates and roots to check each signature, see where the chain ends, and whether it reaches a root in the Mozilla CA store.
- **Hostname match:** enter a hostname to check it against the certificate's SANs (wildcards included).
- **Live site check:** enter `example.com` (and optionally a port) and the server fetches the certificate chain it presents, plus the TLS version and cipher.
- **Warnings:** weak RSA keys, SHA-1/MD5 signatures, certificates expiring within 30 days, self-signed leaves, and validity periods over 398 days.

**Create**
- **Generate keys:** create a key pair with a self-signed certificate, a CSR, or keys only. Supports RSA 2048/3072/4096, ECDSA P-256/P-384/P-521 and Ed25519, with SHA-256/384/512, SANs, subject fields, validity and a CA option. Results can be copied, downloaded as PEM, or sent straight to the validator.
- **History:** generated key pairs are saved under a name (rename or delete any time). History is stored only in your browser's local storage, unencrypted, and you choose whether the private key is included. The server never stores generated keys.

Not covered yet: revocation (CRL/OCSP).

- `server.js` — Express app and API routes
- `lib/` — certificate parsing (`certificate.js`), chain/hostname analysis (`analysis.js`), live TLS fetch with SSRF protection (`liveCheck.js`), key generation (`keygen.js`)
- `test/` — tests (`npm test`)
- `public/` — static frontend (HTML/CSS/JS) served by the server

## Prerequisites

- [Node.js](https://nodejs.org/) (includes npm)

## Start

```bash
npm install
npm start
```

The app runs at [http://localhost:3003](http://localhost:3003) — the server also serves the frontend from `public/`, so there's nothing else to start.

For development with auto-restart on file changes:

```bash
npm run dev
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3003` | Port to listen on |
| `CORS_ORIGIN` | unset (CORS off) | Comma-separated origins allowed to call the API cross-origin |
| `TRUST_PROXY` | unset | Set (e.g. `1`) when behind a reverse proxy so rate limiting sees client IPs |
| `ALLOW_PRIVATE_HOSTS` | unset | Set to `1` to let live checks reach private/loopback addresses (local use only) |

Uploads are limited to 1 MB and the extensions above, are processed in memory, and are never written to disk. Validation requests are rate limited to 60/min and live checks to 10/min per client.

## Tests

```bash
npm test
```

## Docker

```bash
docker compose up -d --build      # build from source and run on http://localhost:3003
APP_VERSION=1.2.3 docker compose up -d   # run the published ghcr.io image for a version
```

Compose settings (all optional): `APP_VERSION` (image tag, default `latest`), `HOST_PORT` (default `3003`), `TRUST_PROXY`, `CORS_ORIGIN`. The container runs as a non-root user with a read-only filesystem and has a `/healthz` health check.

## Versioning and releases

The version lives in one place: `package.json`. It is shown in the app footer and at `/api/version`, and it tags the Docker images.

```bash
node scripts/release.js --show     # print the current version
node scripts/release.js patch      # or minor / major / x.y.z: bump, commit and tag vX.Y.Z
git push origin HEAD vX.Y.Z        # the pushed tag publishes the image
```

The GitHub Actions workflow (`.github/workflows/docker.yml`) runs the tests, then builds the image:

| Event | Result |
| --- | --- |
| Tag `vX.Y.Z` | Publishes `ghcr.io/<owner>/certificate-validator` as `X.Y.Z`, `X.Y` and `latest` (fails if the tag does not match `package.json`) |
| Push to `main` | Publishes `latest`, `edge` and `sha-<commit>` (no version tag) |
| Pull request | Tests and builds only, nothing is published |

## Stop

Press `Ctrl+C` in the terminal running the server.

If it's running in the background and you need to force-stop it:

```bash
# Windows
taskkill /F /IM node.exe

# macOS/Linux
pkill -f "node server.js"
```
