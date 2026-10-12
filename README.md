# Certificate Workbench

A small web app for validating, decoding, converting and creating X.509 certificates, keys and CSRs.

## Features

**Validate**
- **Upload or paste** a certificate (PEM, CRT, CER, DER, PFX/P12) and see validity, subject/issuer, serial number, fingerprints, key usage, SANs and more.
- **Chain verification:** include intermediates and roots to check each signature, see where the chain ends, and whether it reaches a root in the Mozilla CA store.
- **Hostname match:** enter a hostname to check it against the certificate's SANs (wildcards included).
- **Live site check:** enter `example.com` (and optionally a port) and the server fetches the certificate chain it presents, plus the TLS version and cipher.
- **Warnings:** weak RSA keys, SHA-1/MD5 signatures, certificates expiring within 30 days, self-signed leaves, and validity periods over 398 days.

**Inspect**
- **Decode CSRs:** subject, public key, requested SANs, key usage and extensions, and whether the request's signature verifies.
- **Decode CRLs:** issuer, dates, CRL number, signature check against an issuer certificate you supply, and every revoked serial. Add certificates next to the CRL to see which of them are listed.
- **Decode bundles:** PKCS#7 / P7B, PEM bundles, PFX/P12 and JKS keystores are unpacked into the certificate report. Private keys are only described, never displayed.

**Create**
- **Generate keys:** create a key pair with a self-signed certificate, a CSR, or keys only. Supports RSA 2048/3072/4096, ECDSA P-256/P-384/P-521 and Ed25519, with SHA-256/384/512, SANs, subject fields, validity and a CA option. Results can be copied, downloaded as PEM, or sent straight to the validator.
- **History:** generated key pairs are saved under a name (rename or delete any time). History is stored only in your browser's local storage, unencrypted, and you choose whether the private key is included. The server never stores generated keys.
- **CSR from an existing key:** build a CSR for a key you already have (PEM, PFX or JKS), optionally copying the subject and names from the certificate you are renewing.

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
                 bundle.js (reads PEM/DER/P7B/PFX/JKS input), convert.js + jks.js (format conversion),
                 decode.js (CSR/CRL/bundle decoding), ca.js (local CA, CSR creation), keys.js
public/          static frontend (HTML/CSS/JS), served by the server
test/            tests (node:test)
scripts/         release.js (version bump + tag)
Dockerfile, docker-compose.yml, .github/workflows/docker.yml
```

## Requirements

- [Node.js](https://nodejs.org/) 22 or newer (includes npm), or
- [Docker](https://www.docker.com/) to run the container image instead.

## Run locally

```bash
npm install
npm start
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

The app is then at [http://localhost:33003](http://localhost:33003). Compose settings (all optional): `APP_VERSION`, `HOST_PORT` (default `33003`), `TRUST_PROXY`, `CORS_ORIGIN`. The container runs as a non-root user with a read-only filesystem and has a `/healthz` health check.

If pulling the image is denied, the package is still private: make it public in the repository's Packages settings, or run `docker login ghcr.io`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `33003` | Port to listen on |
| `CORS_ORIGIN` | unset (CORS off) | Comma-separated origins allowed to call the API cross-origin |
| `TRUST_PROXY` | unset | Set when behind a reverse proxy so rate limiting sees client IPs. Use the number of proxy hops (`1` for a single proxy), or a comma-separated list of proxy IPs/subnets (`loopback, 172.16.0.0/12`). `true` trusts every hop and lets clients spoof their IP, so prefer a number or a list. |
| `ALLOW_PRIVATE_HOSTS` | unset | Set to `1` to let live checks reach private/loopback addresses (local use only) |
| `APP_VERSION` | from `package.json` | Version shown in the app; set by the Docker build |

Uploads are limited to 1 MB and the supported extensions, are processed in memory, and are never written to disk. Rate limits per client: 60 validations/min, 20 key generations/min, 10 live checks/min.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /api/validate-certificate` | Multipart form: `certificate` (file) or `certText`, plus optional `password` and `hostname` |
| `POST /api/check-host` | JSON `{ "host": "example.com", "port": 443 }`: fetch and analyse a server's chain |
| `POST /api/generate-keypair` | JSON options (`algorithm`, `output`, `commonName`, `sans`, `hash`, `validityDays`, ...): returns the keys and certificate or CSR. Nothing is stored. |
| `POST /api/decode` | Multipart: `files` and/or `text` (CSR, CRL, P7B, PEM, PFX, JKS), optional `password` |
| `POST /api/convert` | Multipart: `files` and/or `text`, `format` (`pem`, `der`, `p7b`, `pfx`, `jks`), `password`, `outputPassword`, `alias`, `legacy` |
| `POST /api/csr/create` | Multipart: `key` file or `keyText`, `keyPassword`, optional `cert`/`certText`, `commonName`, `sans`, `hash`, subject fields |
| `POST /api/ca/create` | Multipart: `commonName`, `algorithm`, `hash`, `validityDays`, `pathLength`, subject fields; for an intermediate also `issuer` file or `issuerText` and `issuerPassword` |
| `POST /api/ca/sign` | Multipart: `csr` file or `csrText`, `ca` file or `caText` (certificate + key), `caPassword`, `usage` (`server`, `client`, `both`, `ca`), `validityDays`, `sans`, `copySans`, `hash` |
| `GET /api/algorithms` | Supported key algorithms |
| `GET /api/version` | Running version |
| `GET /healthz` | Health check |

## Private keys

Endpoints that take private keys (convert, CSR creation, signing) process them in memory, send `Cache-Control: no-store`, and never log them.

## Tests

```bash
npm test
```

## Versioning and releases

The version lives in one place: `package.json`. It is shown in the app footer and at `/api/version`, and it tags the Docker images.

To publish a new version:

1. Merge your changes to `main` and update your local copy (`git checkout main && git pull`). The working tree must be clean.
2. Bump the version, commit and tag it:
   ```bash
   node scripts/release.js patch    # or minor / major / x.y.z. Use --show to print the current version.
   ```
3. Push the commit and the tag the script prints:
   ```bash
   git push origin main vX.Y.Z
   ```

The GitHub Actions workflow (`.github/workflows/docker.yml`) runs the tests, then builds the image:

| Event | Result |
| --- | --- |
| Tag `vX.Y.Z` | Publishes `ghcr.io/<owner>/certificate-workbench` as `X.Y.Z`, `X.Y` and `latest` (fails if the tag does not match `package.json`) |
| Push to `main` | Publishes `latest`, `edge` and `sha-<commit>` (no version tag) |
| Pull request | Tests and builds only, nothing is published |

`edge` always tracks the newest `main`, `latest` is the newest push or release, and a version tag such as `1.1.1` never changes, so pin that in deployments. The workflow needs read and write access to packages: Settings, then Actions, then General, then Workflow permissions.
