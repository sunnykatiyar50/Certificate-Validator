# Certificate Workbench

A small web app for validating, decoding, converting and creating X.509 certificates, keys and CSRs, behind a sign-in with an admin and regular users.

## Features

**Validate**
- **Upload or paste** a certificate (PEM, CRT, CER, DER, PFX/P12) and see validity, subject/issuer, serial number, fingerprints, key usage, SANs and more.
- **Chain verification:** include intermediates and roots to check each signature, see where the chain ends, and whether it reaches a root in the Mozilla CA store.
- **Hostname match:** enter a hostname to check it against the certificate's SANs (wildcards included).
- **Live site check:** enter `example.com` (and optionally a port) and the server fetches the certificate chain it presents, plus the TLS version and cipher.
- **Warnings:** weak RSA keys, SHA-1/MD5 signatures, certificates expiring within 30 days, self-signed leaves, and validity periods over 398 days.
- **Root programs:** for a chain that reaches a root, see whether that root is in the Mozilla, Apple, Chrome and Microsoft root stores. Mozilla uses the store bundled with Node.js; the others use CCADB data saved in `trust-data/root-stores.json` (see [Root store data](#root-store-and-ct-log-data)).
- **Certificate Transparency:** embedded SCTs are listed with the log name, operator and time, and publicly trusted certificates without any get an informational note. SCTs delivered in the TLS handshake or OCSP response are not checked.

**Inspect**
- **Decode CSRs:** subject, public key, requested SANs, key usage and extensions, and whether the request's signature verifies.
- **Decode CRLs:** issuer, dates, CRL number, signature check against an issuer certificate you supply, and every revoked serial. Add certificates next to the CRL to see which of them are listed.
- **Decode bundles:** PKCS#7 / P7B, PEM bundles, PFX/P12 and JKS keystores are unpacked into the certificate report. Private keys are only described, never displayed.
- **Match a key pair:** compare the public keys of any mix of private keys, certificates and CSRs to confirm which belong together.

**Create**
- **Generate keys:** create a key pair with a self-signed certificate, a CSR, or keys only. Supports RSA 2048/3072/4096, ECDSA P-256/P-384/P-521 and Ed25519, with SHA-256/384/512, SANs, subject fields, validity and a CA option. Results can be copied, downloaded as PEM, or sent straight to the validator.
- **History:** generated key pairs are saved under a name (rename or delete any time). Users see only their own history and the admin sees everyone's. The server stores the certificate, CSR, public key and details, but never a private key: if you choose to keep one, it stays in your browser only (unencrypted).
- **CSR from an existing key:** build a CSR for a key you already have (PEM, PFX or JKS), optionally copying the subject and names from the certificate you are renewing.

**Accounts and appearance**
- Sign-in with an admin from `.env` plus regular users (see [Authentication](#authentication)).
- Light, dark or system theme, on the login page and in the app.

**Local CA**
- **Create a CA:** a root CA, or an intermediate signed by a CA you supply. Choose the algorithm, validity and path length. The CA key is returned once and never stored.
- **Sign a CSR:** issue a TLS server, TLS client or intermediate-CA certificate from a CSR with your CA. Names are copied from the CSR (or added), validity is limited to the CA's lifetime, and the result comes with the CA chain. The CA key is sent to the server for the request, held in memory and discarded.

**Convert**
- Convert between **PEM, DER, PKCS#7 (P7B), PFX/PKCS#12 and JKS**. Paste or upload the certificate, chain and key in any order and any mix; the chain is ordered leaf-first and the key is checked against the leaf. PFX files can use AES-256 or legacy 3DES for old Windows and Java; PEM private keys can be encrypted. RSA, ECDSA and Ed25519 keys are supported. CSRs and CRLs convert between PEM and DER.

Not covered yet: fetching revocation data online (OCSP, CRL downloads). A CRL you supply can be decoded and checked against certificates.

## Project structure

```
server.js        Express app and API routes
lib/             certificate.js (parsing), analysis.js (chain/hostname/warnings),
                 liveCheck.js (live TLS fetch, SSRF protection), keygen.js (key generation),
                 auth.js (accounts, sessions), historyStore.js (per-user history in SQLite),
                 assets.js (cache-busting fingerprints for the frontend files),
                 bundle.js (reads PEM/DER/P7B/PFX/JKS input), convert.js + jks.js (format conversion),
                 decode.js (CSR/CRL/bundle decoding), match.js (key matching), ca.js (local CA, CSR creation),
                 sct.js (Certificate Transparency), rootStores.js (Apple/Chrome/Microsoft membership), keys.js
trust-data/      root-stores.json and ct-logs.json (generated, see scripts/update-trust-data.js)
public/          static frontend (HTML/CSS/JS, login page), served by the server
test/            tests (node:test)
scripts/         release.js (version bump + tag), hash-password.js (password hashes, session secret),
                 update-trust-data.js (refresh trust-data/)
Dockerfile, docker-compose.yml, .github/workflows/docker.yml
```

## Requirements

- [Node.js](https://nodejs.org/) 22.13 or newer (includes npm; the history database uses Node's built-in SQLite), or
- [Docker](https://www.docker.com/) to run the container image instead.

## Run locally

The app needs sign-in settings, or it refuses to start. Copy `sample.env` to `.env`, fill in `ADMIN_PASSWORD` and `SESSION_SECRET`, and load them into your shell (or use your editor's env support). For quick local use without a login:

```bash
npm install
AUTH_DISABLED=1 npm start      # PowerShell: $env:AUTH_DISABLED=1; npm start
```

The app runs at [http://localhost:33003](http://localhost:33003). The server also serves the frontend from `public/`, so there is nothing else to start.

For development with auto-restart on file changes:

```bash
npm run dev
```

Stop it with `Ctrl+C`. If it is running in the background and you need to force-stop it:

```bash
# Windows
taskkill /F /IM node.exe

# macOS/Linux
pkill -f "node server.js"
```

## Run with Docker

First create your settings: copy `sample.env` to `.env`, then set at least `ADMIN_PASSWORD` and `SESSION_SECRET` (Compose refuses to start without them). See [Authentication](#authentication).

```bash
cp sample.env .env
```

Build from source and run:

```bash
docker compose up -d --build
```

Run a published image from GitHub Container Registry (no source needed). `APP_VERSION` picks the tag and defaults to `latest`:

```bash
# bash / WSL / macOS / Linux
APP_VERSION=1.1.1 docker compose up -d
```

```powershell
# PowerShell
$env:APP_VERSION = "1.1.1"; docker compose up -d
Remove-Item Env:APP_VERSION   # clear it afterwards
```

You can also keep the settings in a `.env` file next to `docker-compose.yml`: copy `sample.env` to `.env` and edit it (for example `APP_VERSION=1.1.1`). Then plain `docker compose up -d` is enough. The container is named `cert-workbench`, so you can use `docker logs cert-workbench` and `docker stop cert-workbench`.

The app is then at [http://localhost:33003](http://localhost:33003). Compose settings: `ADMIN_PASSWORD` and `SESSION_SECRET` are required; `ADMIN_USERNAME`, `USERS`, `SESSION_TTL_HOURS`, `APP_VERSION`, `HOST_PORT` (default `33003`), `TRUST_PROXY` and `CORS_ORIGIN` are optional. The container runs as a non-root user with a read-only filesystem and has a `/healthz` health check. The history database is kept in the `cert-workbench-data` volume (mounted at `/app/data`), so it survives restarts and upgrades.

If pulling the image is denied, the package is still private: make it public in the repository's Packages settings, or run `docker login ghcr.io`.

**Behind a reverse proxy or CDN** (Nginx Proxy Manager, Traefik, Cloudflare, ...): the server adds a content fingerprint to the stylesheet and script links in its pages (`style.css?v=3f9a1c0d2b`), so a new release always loads new files even if the proxy caches static assets. Pages are never cached, and assets requested without a current fingerprint are marked `no-cache`. No cache purge is needed after an upgrade. If a page ever looks unstyled, open `/style.css` on your domain and compare it with the one on the server, and check the proxy's asset caching settings.

The first line of the log shows which build is running, for example `Certificate Workbench v2.1.0 (Node.js v22.23.2)`, and the line when it is ready lists the version, whether sign-in is on, and the data folder.

## Authentication

Every page and API (except `/healthz`, `/api/version` and the login page) needs a signed-in user. Accounts come from environment variables, as in `sample.env`:

| Variable | Purpose |
| --- | --- |
| `ADMIN_USERNAME` | Admin account name (default `admin`) |
| `ADMIN_PASSWORD` | Admin password, at least 8 characters, or a hash. **Required.** |
| `USERS` | Regular users: `alice:password,bob:password`. Optional. |
| `SESSION_SECRET` | At least 32 random characters; signs the session cookie. **Required.** |
| `SESSION_TTL_HOURS` | Sign-in lifetime, default `12` |
| `AUTH_DISABLED` | `1` skips sign-in entirely (everyone is an admin). Local development only. |

The server refuses to start, and logs what is wrong, if a required value is missing, too short, or still a `change-me` placeholder.

- **Roles:** the admin and users can use every feature. In History, users see only their own items; the admin sees everyone's and can filter by user, rename or delete any item.
- **Hashed passwords:** instead of plain text you can store a hash: `npm run hash-password` prompts for a password and prints a value to use for `ADMIN_PASSWORD` or in `USERS=name:hash`. With Docker: `docker run --rm -it ghcr.io/sunnykatiyar50/certificate-workbench node scripts/hash-password.js`. Generate a `SESSION_SECRET` with `npm run hash-password -- --secret`.
- **Sessions:** a signed cookie (`HttpOnly`, `SameSite=Strict`, `Secure` when served over HTTPS, so set `TRUST_PROXY` behind a TLS proxy). Changing a user's password, removing the user, or changing `SESSION_SECRET` signs them out. Sign-out only clears the browser's cookie; a stolen cookie stays valid until it expires.
- **Protections:** failed sign-ins are limited to 10 per 15 minutes per address, state-changing requests need an `X-Requested-With` header (CSRF), and responses carry a strict Content-Security-Policy.
- **Private keys:** the server never stores them. If you keep one with a history item, it is saved in that browser only, per user, unencrypted.
- **Changing accounts** means editing `.env` and restarting the container. History is tied to the username, so renaming a user detaches their old items (the admin can still see and delete them).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `33003` | Port to listen on |
| `CORS_ORIGIN` | unset (CORS off) | Comma-separated origins allowed to call the API cross-origin |
| `TRUST_PROXY` | unset | Set when behind a reverse proxy so rate limiting sees client IPs. Use the number of proxy hops (`1` for a single proxy), or a comma-separated list of proxy IPs/subnets (`loopback, 172.16.0.0/12`). `true` trusts every hop and lets clients spoof their IP, so prefer a number or a list. |
| `ALLOW_PRIVATE_HOSTS` | unset | Set to `1` to let live checks reach private/loopback addresses (local use only) |
| `DATA_DIR` | `./data` (`/app/data` in Docker) | Where the history database (`history.db`) is stored |
| `APP_VERSION` | from `package.json` | Version shown in the app; set by the Docker build |

Uploads are limited to 1 MB and the supported extensions, are processed in memory, and are never written to disk. Rate limits per client: 60 validations/min, 20 key generations/min, 10 live checks/min.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /auth/login`, `POST /auth/logout`, `GET /auth/status` | Sign in (JSON `username`, `password`), sign out, current user |
| `POST /api/validate-certificate` | Multipart form: `certificate` (file) or `certText`, plus optional `password` and `hostname` |
| `POST /api/check-host` | JSON `{ "host": "example.com", "port": 443 }`: fetch and analyse a server's chain |
| `POST /api/generate-keypair` | JSON options (`algorithm`, `output`, `commonName`, `sans`, `hash`, `validityDays`, ...): returns the keys and certificate or CSR. Nothing is stored. |
| `POST /api/decode` | Multipart: `files` and/or `text` (CSR, CRL, P7B, PEM, PFX, JKS), optional `password` |
| `POST /api/match` | Multipart: `files` and/or `text` holding keys, certificates and CSRs, optional `password` |
| `POST /api/convert` | Multipart: `files` and/or `text`, `format` (`pem`, `der`, `p7b`, `pfx`, `jks`), `password`, `outputPassword`, `alias`, `legacy` |
| `POST /api/csr/create` | Multipart: `key` file or `keyText`, `keyPassword`, optional `cert`/`certText`, `commonName`, `sans`, `hash`, subject fields |
| `POST /api/ca/create` | Multipart: `commonName`, `algorithm`, `hash`, `validityDays`, `pathLength`, subject fields; for an intermediate also `issuer` file or `issuerText` and `issuerPassword` |
| `POST /api/ca/sign` | Multipart: `csr` file or `csrText`, `ca` file or `caText` (certificate + key), `caPassword`, `usage` (`server`, `client`, `both`, `ca`), `validityDays`, `sans`, `copySans`, `hash` |
| `GET /api/algorithms` | Supported key algorithms |
| `GET/POST/DELETE /api/history`, `PATCH/DELETE /api/history/:id` | The caller's history (admins: everyone's, `?owner=` filters). Private keys are rejected. |
| `GET /api/version` | Running version (public) |
| `GET /healthz` | Health check (public) |

## Root store and CT log data

Apple, Chrome and Microsoft root membership and Certificate Transparency log names are saved in `trust-data/` so the app works offline. Refresh them from the [CCADB](https://www.ccadb.org/) and Google's public log list with:

```bash
npm run update-trust-data
```

Microsoft membership is limited to roots with the Server Authentication purpose and Chrome's store is TLS-only. Apple's list includes every root in Apple's program, whatever its purpose. Mozilla needs no file: Node.js bundles its current store.

Endpoints that take private keys (convert, CSR creation, signing) process them in memory, send `Cache-Control: no-store`, and never log them.

## Tests

```bash
npm test
```

## Versioning and releases

The version lives in one place: `package.json`. It is shown in the app footer and at `/api/version`, and it tags the Docker images.

To publish a new version:

1. Merge your changes to `main` and update your local copy:
   ```bash
   git checkout main
   git pull
   ```
2. Release. The script bumps the version, commits, tags, and publishes the commit and the tag in one atomic push:
   ```bash
   node scripts/release.js patch --push    # or minor / major / x.y.z. Use --show to print the current version.
   ```
   Without `--push` it stops after tagging and prints the command to run yourself: `git push --atomic origin main vX.Y.Z`.

The script refuses to release unless you are on `main`, the working tree is clean, `main` is exactly level with `origin/main` (not behind or ahead), and the tag does not already exist locally or on GitHub. That keeps a stale checkout from publishing an old build under a new version number. Always push the commit and the tag together (`--atomic`): pushed separately, git can reject the branch yet still publish the tag.

The workflow also checks that a release tag is on `main` and fails before building if it is not. If that happens, update `main`, delete the tag (`git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z`) and release again.

The GitHub Actions workflow (`.github/workflows/docker.yml`) runs the tests, then builds the image:

| Event | Result |
| --- | --- |
| Tag `vX.Y.Z` | Publishes `ghcr.io/<owner>/certificate-workbench` as `X.Y.Z`, `X.Y` and `latest` (fails if the tag does not match `package.json`) |
| Push to `main` | Publishes `latest`, `edge` and `sha-<commit>` (no version tag) |
| Pull request | Tests and builds only, nothing is published |

`edge` always tracks the newest `main`, `latest` is the newest push or release, and a version tag such as `1.1.1` never changes, so pin that in deployments. The workflow needs read and write access to packages: Settings, then Actions, then General, then Workflow permissions.
