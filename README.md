# A2B by VEX — Operación v2.4 / Bridge v1.3

## Instalación y seguridad
- Servir A2B desde el **mismo dominio** que el Bridge. Las llamadas a Aspel y las APIs de operaciones usan la cookie de equipo HttpOnly/Secure.
- Configura `A2B_SECRET` (mínimo 24 caracteres, generado aleatoriamente) en las variables privadas del servidor. **No publiques secretos ni credenciales en GitHub**.
- Entra a `/setup`, autoriza al administrador y pulsa **Vincular equipo y abrir A2B**. Ya no se copia ni entrega un token al HTML, localStorage, captura o chat.
- Aspel utiliza las variables privadas `ASPEL_RFC`, `ASPEL_USER`, `ASPEL_PASSWORD` o el archivo cifrado del Bridge. Para persistencia real entre redeploys, usa almacenamiento persistente o credenciales de entorno.
- El service worker deja de cachear `/api/*` y `/setup`. La migración elimina el token antiguo del almacenamiento local.
- **Importante**: el repositorio `vexfumigaciones-afk/a2b` sigue siendo público; la seguridad de APIs depende de que **ningún secreto** esté en el código ni archivos de seguimiento. Mantén los secretos en tu gestor de variables y rota los que se hayan expuesto.

## Centro de operaciones
Desde **Operación**:
1. Configura los días y las horas laborales. Es un cambio administrativo, sujeto a autorización de Setup.
2. Al guardar servicios, el navegador sincroniza los metadatos operativos con `/api/ops/sync`, protegidos mediante cifrado AES-256-GCM en el servidor. Cada dispositivo conserva su propio origen y los registros no se duplican al reintentar.
3. El servidor prepara una cola diaria para los servicios de ese día a partir de las **06:00, hora America/Monterrey**, incluso si se reinicia después de la hora (en cuanto vuelve a estar en línea).
4. Abre la cola y selecciona **Imprimir órdenes del día** para generar una tirada. Los documentos *programados* se distinguen de las órdenes *cerradas y firmadas*.
5. Maps abre la dirección de cada servicio en el navegador, sin requerir una API Key.
6. El editor visual permite arrastrar los campos del certificado y de la orden, ajustar posición, tamaño, color y prefijos de texto. El contenido oficial se extrae del servicio o certificado, no se suplanta mediante la plantilla.
7. Una fotografía comprimida por técnico se incorpora a la impresión cuando coincide su nombre.
8. El certificado independiente registra un motivo y la persona que autorizó la excepción; no supone un permiso administrativo verificable.

## Limitaciones operativas
- **Impresión física completamente desatendida**: NO está habilitada. Una aplicación web en la nube no puede enviar silenciosamente documentos a una impresora local sin un agente de impresión autorizado, un servicio de spooler y una impresora configurada. Sí queda automatizada la *preparación de la cola* en el servidor y se permite imprimir el lote en un clic.
- El editor visual y la base principal A2B siguen almacenándose en el navegador actual. La cola cifrada es un respaldo operativo de servicios, pero todavía no sincroniza clientes, firmas, archivos ni plantillas entre dispositivos.
- Para que la cola sobreviva un redeploy de Render, configura un volumen para `DATA_DIR` (por ejemplo `/data`). En hosting gratuito sin disco persistente el archivo `operations.enc` puede perderse.
- El automatismo de las 06:00 requiere un servidor activo; en planes que duermen o se suspenden el lote se prepara en la primera activación posterior.
- Aún se requieren pruebas reales con la cuenta Aspel, certificados y una impresora física antes de liberar a producción.

## Comprobaciones
`npm run check` revisa sintaxis del Bridge y los módulos de operaciones.
`GET /api/health` reporta Bridge v1.3.0.
`GET /api/ops/daily?date=AAAA-MM-DD` consulta la cola del día para un dispositivo vinculado.
No uses un navegador público o compartido para autorizar `/setup`.
