# Probar la beta

Esta variante tiene habilitado el intento de jailbreak. La revisión d297586 (r134.a1) llegó en un iPhone X, iOS 16.7.15, hasta jailbreakd autenticado, y el usuario confirmó que Sileo y RootHide Manager abren después de «Actualizar aplicaciones del jailbreak». Zebra todavía se cierra y Sileo detectó la dependencia libkrw0-plugin ausente. Esto es evidencia parcial de hardware, no validación de todo el jailbreak; los cambios posteriores siguen sin probarse físicamente.

La nueva candidata elimina el filtro de CPU arm64e y contempla iOS 15, 16, 17, 18 y 26. La combinación de exploits de Dopamine decide qué dispositivo y versión pueden continuar. Consulta la [tabla de compatibilidad](README.md#compatibilidad). La primera release mantiene los límites anteriores.

## Instalación

1. Haz una copia de tus datos y usa un iPhone de pruebas, sin otro jailbreak o bootstrap instalado.
2. Descarga la IPA de [Releases](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/releases).
3. Refírmala con AltStore u otro instalador compatible. La IPA lleva firma ad hoc; todavía no se ha probado la instalación con estos servicios.
4. Abre la app y comprueba la compatibilidad antes de pulsar Jailbreak.

Cada intento empieza sin tweaks. Si termina bien, puedes solicitar la inyección desde los ajustes de la app y reiniciar el espacio de usuario. Ese paso tampoco está probado en hardware.

La instalación inicial incluye RootHide Manager y los gestores que selecciones: Sileo y, opcionalmente, Zebra. No incluye arm64ePatcher.

## Reparación puntual de la dependencia libkrw (RootHide 3)

El bootstrap RootHide incluye `libkrw0`, cuyo paquete depende del proveedor virtual `libkrw0-plugin`. La biblioteca `libkrw-dopamine.dylib` ya se instala en el directorio oculto, pero las primeras betas no registraban el proveedor en la base de datos de dpkg. Esta variante incorpora el `libkrw0-dummy.deb` oficial de RootHide (metadatos sin binarios), fijado por SHA-256, y lo instala en nuevas instalaciones antes de Sileo/Zebra.

**Si ya está instalado RootHide 3 y Sileo da ese error**, no borres ni reinstales el bootstrap. Tras instalar una versión de la app que incluya esta corrección, con RootHide activo entra en **Ajustes → Reparar dependencia libkrw (Sileo)** y confirma una sola vez. La acción comprueba que la biblioteca real está presente en el root verificado y usa la instalación autenticada de paquetes para registrar únicamente el proveedor virtual. Si aparece timeout, comparte el diagnóstico y no repitas la acción. Después actualiza fuentes en Sileo y verifica que APT ya permite resolver dependencias.

El cierre de Zebra no se considera arreglado por esta reparación. Si continúa, comparte el informe de fallo específico de Zebra en Cr4shed o Ajustes → Privacidad y seguridad → Análisis y mejoras → Datos de análisis; no reinstales el gestor hasta conocer la causa.

## Contraseña de mobile (diagnóstico posterior a r134)

En la prueba del iPhone X con r134, `pw usermod 501 -h 0` devolvió dos veces el código 67 tras completarse la autenticación y el parcheo del proceso. En `sysexits`, 67 corresponde a `EX_NOUSER`; los archivos `etc/master.passwd` de los dos bootstraps fijados sí contienen `mobile` con UID 501. La corrección del código utiliza el nombre `mobile` y `pw -V <hidden-root>/etc` para apuntar explícitamente a la base privada; verifica su ubicación, propietario, estado anterior y cambio real del hash. No se ha validado todavía el cambio en hardware.

**Nunca introduzcas tu contraseña en un log, issue o mensaje de diagnóstico.** Si una prueba devuelve error, no reintentes el cambio repetidamente ni edites a mano `master.passwd`/`spwd.db`. Comparte únicamente las etapas y códigos numéricos del diagnóstico.

## Inyección después de repetir Jailbreak, NewTerm y SSH

La prueba en hardware posterior a r138 observó que los tweaks podían funcionar
solo después de actualizar las aplicaciones y reiniciar el espacio de usuario.
Se ha corregido el comportamiento que **recreaba forzosamente**
`basebin/.safe_mode` en cada nuevo intento de jailbreak, aunque el bootstrap
ya estuviera instalado. En la primera activación se sigue forzando el modo
seguro; a partir de entonces se conserva la elección registrada del usuario.
El botón de inyección comprueba ahora el resultado de modificar el marcador y
no ofrece un reinicio si la operación falla.

La opción **Ajustes → Diagnosticar tweaks, NewTerm y SSH** es de solo lectura:
registra si existen el marcador de modo seguro, TweakLoader, el bundle NewTerm,
el ejecutable sshd y plists SSH del root verificado. No almacena las rutas
privadas completas, no cambia contraseñas ni inicia servidores. **Encontrar un
plist o binario no demuestra que el daemon esté en ejecución.** Para un fallo de
NewTerm hace falta además el informe de cierre o el mensaje en pantalla; para
SSH, distinguir «conexión rechazada», «tiempo agotado» y «autenticación fallida».
El registro de apps no se ejecuta automáticamente durante el primer arranque
porque una versión anterior se bloqueaba en el primer hijo parcheado.

## Si falla

Guarda el mensaje de error, los logs, el modelo, la versión exacta de iOS y la revisión de la app. No repitas el proceso sin revisar el fallo: puede haber quedado un bootstrap a medias. No se borra automáticamente una instalación de RootHide 2, y reiniciar no garantiza resolver cualquier estado parcial.

## Compilar esta variante

Los builds normales mantienen el jailbreak desactivado. La variante habilitada se genera manualmente con `hardware_beta` en GitHub Actions o, en macOS con las dependencias del proyecto:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 ROOTHIDE_HARDWARE_TEST=YES gmake NIGHTLY=1
python3 tools/verify_roothide_full_experimental.py --hardware-beta --ipa Application/Dopamine.ipa --json
```

El identificador de esta app es `com.gokuencinar.roothide3.hardwarebeta`. Compilar y revisar el paquete no sustituye las [pruebas en un iPhone](validation/README.md).
