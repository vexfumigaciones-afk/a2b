# A2B by VEX — Bridge v0.8

Esta versión corrige el fallo de build de Render causado por incrustar HTML/base64 enorme dentro de un heredoc del Dockerfile.

## Archivos que deben quedar en GitHub

- `Dockerfile`
- `package.json`
- `server.js`
- `lib/crypto-store.js`
- `lib/aspel.js`
- `public/index.html`
- `public/setup.html`
- `public/manifest.webmanifest`
- `public/sw.js`
- `public/icon-192.png`
- `public/icon-512.png`

## Render

- Runtime: Docker
- Root Directory: vacío
- Dockerfile Path: `./Dockerfile`
- Health Check Path: `/api/health`
- Environment: `A2B_SECRET` (mínimo 24 caracteres)

No subas credenciales Aspel a GitHub. Se capturan en `/setup`.
