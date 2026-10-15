# Incidencias revisadas durante el port

Estas notas recogen la revisión del 14 de octubre de 2026. Sirven para orientar las pruebas; una incidencia de otro proyecto no demuestra que este port tenga el mismo fallo.

## Cambios aplicados

Se corrigió la inserción de varias páginas de trustcache, el manejo de fallos de memoria y el orden de los hooks que marcan las peticiones XPC. Se tomó como referencia [Dopamine2-roothide](https://github.com/roothide/Dopamine2-roothide) y la [documentación de ElleKit](https://github.com/tealbathingsuit/ellekit/blob/main/Usage.md).

La revisión posterior de firmas está en [SIGNATURE-FIXES-2026-10-15.md](SIGNATURE-FIXES-2026-10-15.md). La adaptación experimental a iOS 18 se describe en [IOS18-SIDELOADING.md](IOS18-SIDELOADING.md).

## Casos que conviene probar

- **Bloqueos de launchd/jailbreakd:** el [PR 142](https://github.com/roothide/Dopamine2-roothide/pull/142) propone cambios, pero la causa fue discutida por el mantenedor. Hace falta un stackshot del bloqueo antes de copiar cambios de colas o timeouts.
- **Reinicio del espacio de usuario en iOS 15 arm64e:** las [versiones 2.4.9.23 y 2.4.9.24](https://github.com/roothide/Dopamine2-roothide/releases) recogen una regresión y su corrección. Hay que probar primer arranque, rejailbreak y reinicio por separado.
- **App Store y AirDrop:** revisar [RootHide 113](https://github.com/roothide/Dopamine2-roothide/issues/113) y [Bootstrap 350](https://github.com/roothide/Bootstrap/issues/350). Que aparezca SpringBoard no basta; hay que probar actualizaciones y transferencias.
- **Preferencias, iconos y notificaciones:** [Bootstrap 335](https://github.com/roothide/Bootstrap/issues/335) ayuda a elegir casos de prueba, aunque Bootstrap usa otra arquitectura de inyección.
- **Selección arm64/arm64e:** [Dopamine 573](https://github.com/opa334/Dopamine/issues/573) describe un fallo histórico corregido en 2.1.5. No se da por reproducido aquí.
- **Sistemas posteriores:** [Dopamine 893](https://github.com/opa334/Dopamine/issues/893) y [Bootstrap 357](https://github.com/roothide/Bootstrap/issues/357) sirven de referencia sobre TXM y restricciones de ejecución. No amplían la compatibilidad de este port.

Quedan pendientes las pruebas de procesos suspendidos, extensiones, prewarm, blacklist y recuperación tras una instalación parcial. También hace falta ampliar las pruebas con Mach-O malformados y revisar las escrituras de `recdhash` antes de dar por cerrada esa parte.

Los resultados reales se guardarán en [validation](validation/README.md). Por ahora hay compilación y comprobaciones del paquete, pero ninguna prueba en un iPhone.
