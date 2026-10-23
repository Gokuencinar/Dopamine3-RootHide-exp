# RootHide 3

Adaptación experimental de RootHide en Dopamine 3.x.

## Compatibilidad

**Objetivo:** llevar RootHide 3 a todos los iPhone y versiones de iOS 16,
17 y 18 para los que Dopamine 3 disponga de una combinación compatible de
exploits de kernel y, cuando sea necesario, de PAC y PPL/SPTM. **No se limita
al iPhone X ni a procesadores arm64.** La compatibilidad de Dopamine original
no implica automáticamente que este port experimental funcione en hardware.

| Generación de chip | iOS 16 | iOS 17 | iOS 18 |
| --- | --- | --- | --- |
| A8–A11 (arm64) | Si el modelo ejecuta esa versión y Dopamine ofrece exploit | Según firmware disponible | Según firmware disponible; solo modelos que realmente ejecuten iOS 18 |
| A12–A13 (arm64e) | Objetivo del port | Objetivo del port | Objetivo hasta 18.7.1 |
| A14–A17 (arm64e) | Objetivo del port | Objetivo hasta 17.3.1 | Sin exploit general en Dopamine 3 |
| A18 y posteriores | No corresponde a esos dispositivos | No corresponde a esos dispositivos | Sin soporte general de Dopamine 3 |

Estos límites son los de [Dopamine oficial](https://ellekit.space/dopamine/),
no resultados de pruebas físicas de RootHide 3. Los iPhone que no puedan
ejecutar determinada versión de iOS quedan naturalmente fuera de esa celda.
La aplicación conserva la selección dinámica de exploits y debe rechazar
cualquier combinación para la que falte algún requisito. La matriz de
**validación pendiente por arquitectura y generación de iOS** está en
[COMPATIBILITY-IOS16-18.md](docs/COMPATIBILITY-IOS16-18.md).

Puedes descargar la IPA en [Releases](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/releases). Necesita instalarse con AltStore u otro sideloader.



Port de **Gokuencinar/GokuEn**, basado en el trabajo de los equipos de [Dopamine](https://github.com/opa334/Dopamine) y [RootHide](https://github.com/roothide). Los créditos originales se conservan en la app.
