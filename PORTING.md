# Notas del port

El objetivo es integrar RootHide en Dopamine 3 conservando su bootstrap aislado. No se usa `/var/jb` como raíz de esta instalación.

## De dónde parte

| Proyecto | Revisión usada |
| --- | --- |
| Dopamine 3.0.11 | `448ff1a83d2bb807346f1f3d36332e4afbf9794a` |
| Dopamine-roothide, rama 3.x | `7e0a9243594b271b3db673bb5194b00be6096ab8` |
| Dopamine2-roothide, donante del port | `e8de6e5035fee52ca732536dbb3ca1734889d914` |

La rama 3.x de RootHide usada como referencia aún no contenía una integración completa. Las partes de RootHide se han adaptado desde el donante de Dopamine 2.

## Estado actual

El port usa contenedores `.jbroot` y App Group, recursos fijados por SHA-256 y el dominio IPC 6 de RootHide. Se han revisado las firmas, la trustcache, el intercambio XPC y la preparación del bootstrap. Hay más detalles en [las notas de firmas](SIGNATURE-FIXES-2026-10-15.md) y [la revisión de incidencias](RESEARCH-ROOTHIDE3-2026-10-14.md).

El perfil del bootstrap es 1800 en iOS 15 y 1900 en iOS 16/18. Para iOS 18 se reutiliza el userspace de RootHide de forma experimental. Los contenedores guardan su versión mayor de sistema y ABI; se rechazan los perfiles incompatibles antes de modificarlos.

La adaptación de dyld y de la información del task se explica en [IOS18-SIDELOADING.md](IOS18-SIDELOADING.md). No se han inventado offsets ni ampliado los rangos de los exploits.

## Compilación y pruebas

La compilación nativa de la candidata `403be34` terminó en macOS y pasó 147 pruebas de host. La IPA publicada con los créditos de Gokuencinar conserva ese código nativo; la revisión de recursos queda registrada dentro del paquete en `credits-resource-revision.json`.

Las comprobaciones del paquete y las pruebas con memoria simulada no prueban el arranque en un iPhone. Faltan pruebas de instalación, launchd/dyld, gestores, ocultación, blacklist, tweaks, reinicios y eliminación.

Los builds normales tienen el jailbreak desactivado. La [Hardware Beta](HARDWARE-BETA.md) lo habilita expresamente para pruebas. La auditoría estricta seguirá sin aprobar el port mientras falten los resultados reales que exige [validation](validation/README.md); publicar esta pre-release no cambia eso.
