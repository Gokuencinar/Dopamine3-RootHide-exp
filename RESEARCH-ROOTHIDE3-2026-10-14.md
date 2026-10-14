# RootHide 3 + Dopamine 3.0.11: investigación y depuración

Fecha: 14 de octubre de 2026. Rama local: `roothide-dopamine3-integration`.
Documento técnico de trabajo; **ninguna prueba de fuente o compilación
constituye evidencia de un jailbreak funcional o de seguridad de arranque**.

## Árboles de referencia verificados

- [Dopamine 3.x oficial](https://github.com/opa334/Dopamine/tree/3.x):
  HEAD `448ff1a` (3.0.11, 13/oct/2026), base del port.
- [Dopamine-roothide, rama 3.x](https://github.com/roothide/Dopamine-roothide/tree/3.x):
  HEAD `7e0a924` (18/sep/2026). Aunque el README anuncia integración en
  curso, este árbol público **no contiene** todavía
  `BaseBin/libjailbreak/src/roothider/`; es una referencia de Dopamine,
  **no una implementación RootHide 3 completa**.
- [Dopamine2-roothide](https://github.com/roothide/Dopamine2-roothide):
  HEAD `e8de6e5` del 08/oct/2026, coincide con el donante local
  `/descargas-cos/RootHide-Dopamine2-ref`. Contiene las rutas RootHide
  de spawn, dyld, firmas y ocultación actualmente utilizadas como donante.
- [Bootstrap 2](https://github.com/roothide/Bootstrap/releases):
  arquitectura de inyección distinta, útil para incidencias reproducibles
  de compatibilidad pero no sustituye a `launchdhook` de Dopamine.
- [ElleKit](https://github.com/tealbathingsuit/ellekit/blob/main/Usage.md):
  documentación de `MSHookFunction`; en el port se añadió `-lellekit`
  a launchdhook y se debe validar ese símbolo en ambas arquitecturas.

## Hallazgos cruzados con la implementación local

| Prioridad | Evidencia externa | Ruta del port y consecuencia | Resolución o prueba requerida |
| --- | --- | --- | --- |
| P1 confirmado | Comparación directa con RootHide2; [Dopamine2-roothide releases](https://github.com/roothide/Dopamine2-roothide/releases) | `BaseBin/libjailbreak/src/trustcache.c`: la inserción de más de una página repetía los primeros hashes y omitía los últimos; el crecimiento fallido podía operar con dirección 0 | **Corregido en esta revisión**: cursor avanzado, fallo explícito de kalloc y VLA reemplazada por heap. Regresión de bloques y errores de memoria. |
| P1 condicionado | Auditoría local de hooks RootHide, con [documentación ElleKit](https://github.com/tealbathingsuit/ellekit/blob/main/Usage.md) | `BaseBin/launchdhook/src/xpc_hook.c` y `BaseBin/libjailbreak/src/roothider/xpc_hook.m`: instalación parcial de hooks podía dejar marcador de petición original en respuesta a app bloqueada | **Corregido en esta revisión**: instalar interceptor de salida primero y autorizar etiquetado solo con ambos hooks listos. Pendiente validación ABI de XPC en iOS. |
| P1 sin resolver | [RootHide2 2.4.5.18](https://github.com/roothide/Dopamine2-roothide/releases) documenta mitigación spinlock iOS15 arm64e; donor `launchdhook/src/roothider.m` | El `spawn_hook.c` portado no efectúa el mismo `jbdSpawnPatchChild` de hijos suspendidos y manejo especial de extensiones/driver/prewarm. `DYLD_IN_CACHE=0` tampoco se aplica por hijo como en el donor | Antes del jailbreak real, diseñar estado de suspensión/resume con rollback por proceso, cubrir exec/SETEXEC y driver y evitar espera ilimitada de launchd. Hardware iOS15 arm64e prioritario. |
| P1 sin resolver | [ChOma](https://github.com/opa334/ChOma) y comparación de parsing/propagación local | `BaseBin/ChOma/src/MachO.c` acepta tamaños de comandos de carga insuficientemente validados, puede omitir dependencias obligatorias mal formadas y devolver éxito; `recdhash.m` puede escribir __TEXT antes de validar totalmente la firma | Añadir pruebas con Mach-O truncado, órdenes de carga sin NUL y ASAN, asegurar retorno fail-closed y escrituras transaccionales antes de activar bootstrap. |
| P1 de reproducción, PR debatido | [PR #142](https://github.com/roothide/Dopamine2-roothide/pull/142) | Watchdog y bloqueo launchd/jailbreakd al registrar exec. El mantenedor [cuestionó](https://github.com/roothide/Dopamine2-roothide/pull/142#issuecomment-5159217937) la causa postulada y la reducción del timeout. | **No cherry-pick automático**. Obtener stackshot con cadena de espera y confirmar dónde se queda el hilo antes de ajustar colas/timeouts. |
| P1 en QA | [RootHide2 versión 2.4.9.23](https://github.com/roothide/Dopamine2-roothide/releases) y corrección en 2.4.9.24 | El reboot de userspace en iOS15 arm64e llegó a causar panic; la versión siguiente corrigió el jailbreak/reboot de ese grupo. | Asegurar paridad de comportamiento en `spawn_hook.c`/boomerang, registrar kernel panic, first-boot y re-jailbreak por separado. |
| P1 en QA | [Dopamine2-roothide #113](https://github.com/roothide/Dopamine2-roothide/issues/113), [Bootstrap #350](https://github.com/roothide/Bootstrap/issues/350) | App Store y AirDrop fallan con RootHide activo en algunos entornos; problema también observado sin regresión de nuestro port | No asumir que SpringBoard visible implica éxito. Ejecutar App Store update, AirDrop y logs installd/appstored antes/después, sin borrar cachés del tester como primera medida. |
| P2 | [Bootstrap release beta4/beta5](https://github.com/roothide/Bootstrap/releases), [Bootstrap #335](https://github.com/roothide/Bootstrap/issues/335) | Inyección en apps/sistema puede provocar crash por prefshook/CFPrefs, pérdida de iconos o reinyección de dependencias antiguas | Probar apertura, actualización y notificaciones con y sin inyección. La arquitectura Bootstrap no puede copiarse tal cual a launchdhook. |
| P2 | [Dopamine #573](https://github.com/opa334/Dopamine/issues/573) | Error histórico al usar una arquitectura no predeterminada en Mach-O fat (upstream resuelto en 2.1.5) | Probar ejecutables con preferencia arm64 y arm64e mediante atributos spawn; no afirmar que sigue roto sin reproducir. |
| Fuera de alcance inicial | [Dopamine #893](https://github.com/opa334/Dopamine/issues/893), [Bootstrap #357](https://github.com/roothide/Bootstrap/issues/357) | Panics de TXM y restricciones AMFI/CoreDevice iOS17+; el primer candidato RootHide3 limita iOS a 15/16 arm64e | Reabrir cuando exista compatibilidad verificada en iOS17+; no extrapolar estos panics a iOS15/16. |

## Casos de prueba necesarios antes de habilitar jailbreak

1. **Compilación/inspección macOS**: slices arm64/arm64e; importaciones de
   ElleKit; entitlements y CodeDirectory; `basebin.tar`, `basebin.tc` y
   configuración de arranque; comprobar hash SHA-256 de la IPA del commit
   exacto y la macro de activación compilada.
2. **Primer arranque sin jailbreak activo**: iPhone arm64e con iOS 15.x o
   16.x, de pruebas y con restauración disponible. Registrar cada fase
   (explotación, root, trustcache, inyección, boomerang, usuarios), sin
   confundir un `PASS` del ZIP con una prueba funcional.
3. **Aislamiento de procesos**: apps normales vs bloqueadas, etiquetas
   UIKitApplication/xpcproxy, extensiones/appex, procesos prewarmed,
   servicios system y WebContent, incluyendo spinlock y dyld compartido.
4. **Recuperación**: reinicio normal, re-jailbreak, userspace reboot,
   desinstalación fallida, rollback de BaseBin y trustcache y safe mode.
   Capturar logs/panics, no diagnosticar por una pantalla negra aislada.
5. **Regresión diaria**: notificaciones push y extensiones, App Store,
   AirDrop, apertura desde Settings, actualización de apps y jailbreak
   previo detectado.

## Estado de este documento

Se aplicaron los arreglos deterministas a trustcache y marcadores XPC.
El resto son **hipótesis/riesgos priorizados** y requiere nuevos cambios y
pruebas. No se ha generado ni instalado aquí una IPA con jailbreak
habilitado. La puerta RootHide permanece desactivada en CI ordinario.
