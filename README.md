# A2B by VEX

Paquete mínimo para desplegar A2B Bridge y conservar la app HTML.

## Archivos
- `Dockerfile`: Bridge autocontenido para Render/Railway. Crea internamente el servidor, cifrado AES-256-GCM, setup y conexión Aspel.
- `A2B_by_VEX.html`: app A2B local-first para Android/WebView.

## Render
1. Crear Web Service desde este repo.
2. Runtime: Docker.
3. Variable obligatoria: `A2B_SECRET` con una clave de al menos 24 caracteres.
4. Health check: `/api/health`.
5. Si se usa disco persistente, montarlo en `/data`.
6. Abrir `/setup` para guardar las credenciales de Aspel cifradas.

No subas RFC, usuario, contraseña de Aspel ni `A2B_SECRET` al repositorio.
