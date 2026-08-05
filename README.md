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

## Stop

Press `Ctrl+C` in the terminal running the server.

If it's running in the background and you need to force-stop it:

```bash
# Windows
taskkill /F /IM node.exe

# macOS/Linux
pkill -f "node server.js"
```
