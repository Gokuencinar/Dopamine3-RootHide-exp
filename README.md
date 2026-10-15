# RootHide 3

Estoy adaptando RootHide a Dopamine 3.0.11. Esta es una primera beta para hacer pruebas: ya incluye el intento de jailbreak, pero todavía no la he probado en un iPhone.

Puedes descargar la IPA en [Releases](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/releases). Necesita instalarse con AltStore u otro sideloader.

## Compatibilidad

En iOS 18, el intento de jailbreak está limitado a **A12 y A13, de iOS 18.0 a 18.7.1**: XS, XS Max, XR, familia 11 y SE de segunda generación. Los modelos con A14 o posterior no son compatibles.


## Qué incluye

- RootHide Manager y Sileo si lo eliges durante la instalación. Zebra es opcional.
- Arranque sin tweaks. Después se pueden solicitar desde Ajustes → inyección de tweaks y reiniciar el espacio de usuario.
- Tus datos y el bootstrap pueden verse afectados si falla el proceso. Haz una copia y usa un móvil de pruebas.

La instalación de gestores, la ocultación, los tweaks y los reinicios siguen pendientes de comprobar en un dispositivo. arm64ePatcher no está incluido.

Tienes los pasos en [la guía de la beta](HARDWARE-BETA.md), los límites de [iOS 18](IOS18-SIDELOADING.md) y las [notas del port](PORTING.md).

Port de **Gokuencinar/GokuEn**, basado en el trabajo de los equipos de [Dopamine](https://github.com/opa334/Dopamine) y [RootHide](https://github.com/roothide). Los créditos originales se conservan en la app.
