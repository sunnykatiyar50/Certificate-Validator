# Changelog

All notable changes to Certificate Workbench. The newest release is shown in the app when you hover the version at the bottom of the sidebar.

Add your notes under **Unreleased** as you work. `node scripts/release.js` moves them under the new version when you release. Use the headings Added, Changed, Fixed, Security, Breaking or Removed, and keep each bullet short and written for users. `**bold**` and `code` work in bullets.

## Unreleased

### Fixed
- Converting to **PFX, JKS or DER** (and any other binary download) failed with "newId is not defined" since 2.0.0. They work again.

## 2.2.0 - 2026-10-12

### Added
- **What's new:** hover (or tap) the version at the bottom of the sidebar to read the release notes for the current version, with earlier releases below.
- A clear **Auto / Light / Dark** theme switch that shows which option is selected, on the login page too.

### Changed
- The sidebar footer is compact and always visible: your name and role with a Sign out button, the theme switch, and the version. The long privacy note moved into the release notes popover.
- The navigation list scrolls on its own, so it fits laptop screens without hiding anything.

### Fixed
- The theme control was below the visible part of the sidebar on typical laptop screens, so it looked like the theme did not work.

## 2.1.1 - 2026-10-13

### Added
- The first line of the server log now shows the version, and the ready line lists the version, whether sign-in is on, and the data folder.

### Fixed
- Pages could look unstyled behind a reverse proxy or CDN that cached an old stylesheet after an upgrade. Stylesheet and script links now carry a content fingerprint, so a new release always loads the new files and no cache purge is needed.

## 2.1.0 - 2026-10-12

### Added
- **Match a key pair:** compare the public keys of any mix of private keys, certificates and CSRs to see which belong together.
- **Root programs:** a chain's root is now checked against the Mozilla, Apple, Chrome and Microsoft root stores, using data bundled with the app so it works offline. Refresh it with `npm run update-trust-data`.
- **Certificate Transparency:** embedded SCTs are listed with the log name, operator and time, and publicly trusted certificates without any get a note.

### Changed
- The bundled trust data lives in `trust-data/`, so the history volume at `data/` can no longer hide it.

## 2.0.2 - 2026-10-12

### Changed
- Releases can no longer be tagged from an out-of-date `main`, and the commit and tag are pushed together. The image workflow also refuses a release tag that is not on `main`.

## 2.0.1 - 2026-10-12

### Fixed
- The startup log no longer prints Node's "SQLite is an experimental feature" warning.

## 2.0.0 - 2026-10-12

### Breaking
- **Sign-in is required.** Set `ADMIN_PASSWORD` and `SESSION_SECRET` (and optionally `USERS`) in `.env`. The container will not start without them. See `sample.env`.
- **History is now stored on the server per user,** not in the browser. Users see only their own items and the admin sees everyone's. Existing browser history can be imported once from the History page.
- Requires Node.js 22.13 or newer. The Docker image and container are now named `certificate-workbench`, and history is kept in the `cert-workbench-data` volume.

### Added
- A login page, a user menu with Sign out, and a light, dark or system theme.
- Private keys are never stored on the server. If you keep one with a history item it stays in your browser only.
- `npm run hash-password` creates password hashes and a session secret.

### Changed
- The project is now called **Certificate Workbench**, since it decodes, converts and creates certificates, keys and CSRs as well as validating them.

## 1.3.0 - 2026-10-12

### Changed
- No functional changes.

## 1.2.0 - 2026-10-12

### Added
- **Convert** between PEM, DER, PKCS#7 (P7B), PFX/PKCS#12 and JKS, including AES-256 or legacy 3DES PFX files.
- **Decode** CSRs, CRLs (with signature check and revoked certificates) and PKCS#7, PFX and JKS bundles.
- **CSR from an existing key,** optionally copying names from the certificate being renewed.
- **Local CA:** create root and intermediate CAs and sign CSRs for TLS server, client or intermediate use.

## 1.1.3 - 2026-10-12

### Added
- `sample.env`, a named `cert-validator` container in Compose, and port 33003 as the default.

### Fixed
- The app crashed on start when `TRUST_PROXY` was set to `true` or a number.

## 1.1.2 - 2026-10-12

### Changed
- Wider layout that uses large screens better, and a scrollable form so its last fields stay reachable.
- A rewritten README with current build, Docker and release steps.

## 1.1.1 - 2026-10-12

### Changed
- Everything now runs from the project root: `npm install`, `npm start` and `npm test`.
- The `latest` image tag follows every push to `main`.

## 1.1.0 - 2026-10-12

### Added
- **Chain verification:** each signature is checked and the chain is traced to the Mozilla CA store.
- **Hostname match** against a certificate's subject alternative names, wildcards included.
- **Live site check:** fetch and analyse the certificate chain a server presents.
- **Warnings** for weak keys, SHA-1 or MD5 signatures, near expiry and long validity.
- **Generate keys:** RSA, ECDSA and Ed25519 key pairs with a self-signed certificate, a CSR, or keys only, plus a saved history.
- A side navigation, Docker and Compose files, and an automatic image build.

## 1.0.0 - 2026-08-05

### Added
- Upload or paste a certificate (PEM, CRT, CER, DER or PFX/P12) and see its validity, subject, issuer, fingerprints, key usage and SANs.
