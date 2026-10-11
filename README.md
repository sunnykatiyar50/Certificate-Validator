# Certificate Validator

A small web app for validating X.509 certificates. Upload a certificate file (PEM, CRT, CER, DER, PFX/P12) or paste certificate text, and see its validity, subject/issuer, serial number, fingerprints, key usage, SANs, and more.

- `backend/` — Express server that parses and validates certificates (`server.js`)
- `public/` — static frontend (HTML/CSS/JS) served by the backend

## Prerequisites

- [Node.js](https://nodejs.org/) (includes npm)

## Start

```bash
cd backend
npm install
npm start
```

The app runs at [http://localhost:3003](http://localhost:3003) — the backend also serves the frontend from `public/`, so there's nothing else to start.

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
cd backend
npm test
```

## Docker

```bash
docker compose up -d --build      # build from source and run on http://localhost:3003
APP_VERSION=1.2.3 docker compose up -d   # run the published ghcr.io image for a version
```

Compose settings (all optional): `APP_VERSION` (image tag, default `latest`), `HOST_PORT` (default `3003`), `TRUST_PROXY`, `CORS_ORIGIN`. The container runs as a non-root user with a read-only filesystem and has a `/healthz` health check.

## Versioning and releases

The version lives in one place: `backend/package.json`. It is shown in the app footer and at `/api/version`, and it tags the Docker images.

```bash
node scripts/release.js --show     # print the current version
node scripts/release.js patch      # or minor / major / x.y.z: bump, commit and tag vX.Y.Z
git push origin HEAD vX.Y.Z        # the pushed tag publishes the image
```

The GitHub Actions workflow (`.github/workflows/docker.yml`) runs the tests, then builds the image:

| Event | Result |
| --- | --- |
| Tag `vX.Y.Z` | Publishes `ghcr.io/<owner>/certificate-validator` as `X.Y.Z`, `X.Y` and `latest` (fails if the tag does not match `package.json`) |
| Push to `main` | Publishes `edge` and `sha-<commit>` |
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
