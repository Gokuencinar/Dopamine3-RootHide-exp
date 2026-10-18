# Diagnóstico del reinicio durante «Inicializando entorno de jailbreak»

Caso: iPhone X (iPhone10,3), iOS 16.7.15. En la versión c17872b,
el dispositivo se reinicia durante «Inicializando entorno de jailbreak»,
no aparece Sileo y desaparece el log de la aplicación.

**Lo que puede afirmarse:** el texto se muestra justo antes de ejecutar
injectRootHideLaunchdHookSafely, que prepara el handshake e inyecta
launchdhook.dylib en PID 1. La instalación de Sileo ocurre después,
durante finalizeRootHideBootstrap. El reinicio no demuestra que el
bootstrap se haya finalizado ni identifica aún si fue un panic de kernel,
una terminación de launchd o un userspace reboot solicitado.

## Nueva instrumentación

Las builds Full Experimental/Hardware Beta escriben checkpoints pequeños
en el **contenedor Documents de la propia app**, archivo
RootHide3-last-attempt.log. El contenido se sincroniza con fsync
antes de las operaciones potencialmente fatales. La app guarda solo
fases/errores resumidos, no volcados completos del kernel.

Tras reiniciar, abrir **la misma aplicación** y seleccionar
**Share RootHide diagnostic log** en el menú. Guardar el TXT y comprobar
si la última etapa fue opainject, boomerang, dyld, instalación de
paquetes o requesting intentional userspace reboot.

**Importante:** la build anterior no guardaba este archivo; no puede
reconstruir sus logs perdidos. No realizar intentos adicionales sobre
un iPhone con datos valiosos, no borrar los contenedores .jbroot
manualmente y no interpretar el reinicio como instalación correcta.
En caso de panic, recoger también los informes panic-full si existen
en Ajustes > Privacidad y seguridad > Análisis y mejoras > Datos del análisis.

Esta instrumentación localiza el punto alcanzado en la app, pero aún
no demuestra que los hooks de PID 1 sean seguros.
