A2B by VEX · Bridge v0.7 / App v2.0

Cambios:
- Navegación Home / Servicios / Clientes / Documentos / Certificados / Aspel / Setup.
- Sesión Aspel persistente cifrada y autorrenovable cuando expira.
- Constancia de Situación Fiscal PDF: lectura local en navegador para autollenar RFC, razón social, CP y régimen.
- Nombre comercial independiente de razón social: certificado usa comercial; factura usa fiscal.
- Cierre de orden permite "Omitir firma" y deja la omisión asentada en orden/PDF.
- Certificado oficial VEX conservado.

Para actualizar Render: reemplaza el Dockerfile del repo por este Dockerfile y haz commit.
IMPORTANTE: la conexión/sesión de Aspel queda estable y se renueva; el llenado/timbrado automático del CFDI sigue en calibración para no emitir facturas incorrectas.
