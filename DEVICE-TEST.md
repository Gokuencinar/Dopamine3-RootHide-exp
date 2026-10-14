# RootHide 3 — test de instalación en iPhone

Esta rama genera **dos artefactos muy diferentes**. No los confundas:

| Artefacto Actions | Uso | Jailbreak disponible |
| --- | --- | --- |
| `RootHide3-Device-Test-APP-ONLY` | Instalar y abrir la GUI en un iPhone de pruebas | **No.** Interfaz informativa sin acciones de instalación/explotación/reinicio |
| `RootHide3-COMPILE-ONLY-NOT-FOR-INSTALL` | Inspección de binarios y build del port | **No verificado. No instalar.** |

El primero incluye `RootHide3-Device-Test.ipa`, con bundle ID
`com.gokuencinar.roothide3.diagnostic` y nombre visible `RootHide 3 Test`.
Se construye con `RH3_INSTALLABLE_DIAGNOSTIC=1`, una rama de UI sin menú de
jailbreak/reinicio/actualización, y una guardia adicional en `DOJailbreaker`
que rechaza llamadas directas. Se eliminan los archivos de bootstrap,
BaseBin y paquetes `.deb` de la app. La macro de activación RootHide sigue
en `0`. **No reemplaza** la app estable de Dopamine.

## Instalación

1. En GitHub Actions, abre el último workflow de tu commit y descarga
   `RootHide3-Device-Test-APP-ONLY`. Descomprime el artefacto y localiza
   `RootHide3-Device-Test.ipa`.
2. La IPA de CI se firma **ad hoc** con `ldid` y un plist de entitlements
   vacío. Esto no es una firma de distribución de Apple. Puedes intentar
   instalarla mediante un instalador compatible con firmas ad hoc, como
   **TrollStore en las versiones de iOS que lo admiten**, o volver a firmarla
   con tu propia identidad/provisioning mediante una herramienta legítima
   de sideloading. No existe compatibilidad de instalación universal.
3. Abre `RootHide 3 Test` y comprueba que aparecen el título y el texto
   «Diagnostic build», sin botones de jailbreak. Registra modelo, versión
   de iOS y cualquier error de instalación, cierre o lanzamiento.
4. Para retirar la prueba, borra únicamente la app `RootHide 3 Test`.
   No ejecutes opciones de desinstalación del jailbreak estable.

**Alcance:** verifica formato de IPA, instalación y lanzamiento de la
interfaz; no verifica que se pueda arrancar un jailbreak RootHide en iOS
15/16/17+, ni instalación oculta, jailbreakd, blacklist, `dyld`, `launchd`,
trustcache, kernel patches o recuperación. Que pueda instalarse una GUI
no demuestra que el port sea funcional.

## Compilación en macOS

Después de compilar BaseBin y dependencias:

```sh
gmake -C Application diagnostic
python3 tools/verify_roothide_device_test.py --ipa Application/RootHide3-Device-Test.ipa --json
```

No ejecutar el objetivo `update` del Makefile raíz en un dispositivo:
está diseñado para el Dopamine convencional y no para la app de prueba.
