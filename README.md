# A2B by VEX — Bridge v1.2 / App v2.3

## Qué cambia
- A2B abre y trabaja sin pedir A2B_SECRET.
- A2B_SECRET queda solo como llave del servidor y para cambios administrativos sensibles.
- Al autorizar Setup una vez, el navegador recibe una cookie administrativa segura de larga duración.
- RFC, usuario y contraseña de Aspel se guardan cifrados en el Bridge y se reutilizan automáticamente.
- Cada operación de Aspel valida/renueva la sesión antes de continuar.
- Session Guardian sigue activo mientras Render esté despierto.
- Clientes: nuevo botón **Traer clientes de Aspel**. El Bridge abre el catálogo Clientes, captura respuestas JSON/AJAX y como respaldo lee la tabla visible, luego A2B mezcla por RFC/ID sin duplicar.

## Persistencia real de credenciales
En Render Free `/data` no es almacenamiento garantizado entre recreaciones/redeploys. Para que RFC/usuario/password sobrevivan incluso si se recrea la instancia, configura una sola vez estas Environment Variables privadas en Render:

- `ASPEL_RFC`
- `ASPEL_USER`
- `ASPEL_PASSWORD`

A2B las lee solo del servidor. No se envían al HTML ni al navegador.

`A2B_SECRET` sigue siendo necesario en Render como llave de cifrado y firma de sesiones, pero ya no se pide para usar Home/Servicios/Clientes/Facturar.

## Actualizar
Sube/reemplaza TODOS los archivos de esta carpeta en la raíz del repo `a2b`, Commit changes y deja que Render redeploye.

Comprueba:
- `/api/health` -> versión `1.2.0`
- A2B -> versión `v2.3`

## Importador de clientes Aspel
Aspel documenta el catálogo de Clientes dentro del menú principal. El importador intenta encontrarlo de forma semántica y detectar datos de clientes desde las respuestas JSON de ADM; si la cuenta usa una variante distinta de la interfaz y devuelve 0 clientes, se requerirá una calibración puntual del selector del catálogo.
