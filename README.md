# RootHide 3

Estoy adaptando RootHide a Dopamine 3.0.11. Esta es una primera beta para hacer pruebas: ya incluye el intento de jailbreak, pero todavía no la he probado en un iPhone.

Puedes descargar la IPA en [Releases](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/releases). Necesita instalarse con AltStore u otro sideloader.

## Compatibilidad

La nueva candidata permite intentar el port en los dispositivos que acepte la combinación de exploits de Dopamine 3, tanto arm64 como arm64e. Sigue siendo experimental; no hay pruebas en un dispositivo físico.

| Grupo | Sistemas contemplados por la base |
| --- | --- |
| arm64 (A8–A11) | iOS 15.0–18.7.1, según el dispositivo |
| A12/A13 | iOS 15.0–18.7.1 y 26.0–26.0.1 |
| A14–A17 y M1/M2 | Hasta iOS 17.3.1, según el dispositivo y los exploits disponibles |

La app consulta los exploits disponibles en el propio dispositivo. Un perfil de bootstrap no basta para declarar compatible una combinación de modelo y versión. Esto no añade iOS 18 a A14 o posteriores.

La release `roothide3-test-1` conserva los límites anteriores: estos cambios necesitan una nueva compilación.

## Qué incluye

- RootHide Manager y Sileo si lo eliges durante la instalación. Zebra es opcional.
- Arranque sin tweaks. Después se pueden solicitar desde Ajustes → inyección de tweaks y reiniciar el espacio de usuario.
- Tus datos y el bootstrap pueden verse afectados si falla el proceso. Haz una copia y usa un móvil de pruebas.

La instalación de gestores, la ocultación, los tweaks y los reinicios siguen pendientes de comprobar en un dispositivo. arm64ePatcher no está incluido.

Tienes los pasos en [la guía de la beta](HARDWARE-BETA.md), los límites de [iOS 18](IOS18-SIDELOADING.md) y las [notas del port](PORTING.md).

Port de **Gokuencinar/GokuEn**, basado en el trabajo de los equipos de [Dopamine](https://github.com/opa334/Dopamine) y [RootHide](https://github.com/roothide). Los créditos originales se conservan en la app.
