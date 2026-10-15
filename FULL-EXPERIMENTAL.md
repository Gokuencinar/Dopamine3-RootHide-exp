# RootHide 3 — Aplicación completa experimental (Dopamine 3.0.11)

Este proyecto genera **dos IPA de prueba distintas** en GitHub Actions:

| Artefacto | Contenido | Funciones de jailbreak |
| --- | --- | --- |
| `RootHide3-Device-Test-APP-ONLY` | App UIKit mínima, dos archivos | Ninguna |
| `RootHide3-FULL-EXPERIMENTAL-JAILBREAK-DISABLED` | Dopamine 3 completo, dependencias BaseBin, hooks y recursos RootHide | Compiladas, **no ejecutables** hasta validar el port |

Existe además una [Hardware Beta](HARDWARE-BETA.md) con el jailbreak habilitado,
generada exclusivamente por ejecución manual con `hardware_beta=true`. No cuenta
con validación en un iPhone y conserva una identidad y artefacto separados.

La variante completa utiliza `com.gokuencinar.roothide3.fulltest`, muestra
`RootHide 3 Experimental` y no debería sustituir el bundle del Dopamine
estable (`com.opa334.Dopamine`). Se genera del código completo usando
`RH3_FULL_APP_EXPERIMENTAL=1`. La protección de arranque consulta
`[DOBootstrapper rootHidePortEnabled]` **antes** de cualquier explotación,
instalación o desinstalación; mientras `ROOTHIDE3_BOOTSTRAP_READY=0`, el
botón de jailbreak, Settings y las acciones de reinicio permanecen desactivadas.
Se bloquean también los comandos CLI heredados de TrollStore/actualización
que podrían interactuar con un jailbreak ya instalado.

La selección **siempre** depende de `ROOTHIDE_EXPERIMENTAL_BUILD=1`,
independientemente de `NIGHTLY`. `NIGHTLY=1` añade únicamente el
identificador de compilación y metadatos; no habilita ni deshabilita las
guardias RootHide. El CI prueba los cuatro cruces de ambas opciones mediante
`make -n` antes de iniciar la compilación real.

## Estado y seguridad

La nueva IPA incluye código y recursos de Dopamine/RootHide, pero **no es un
jailbreak funcional**. Queda trabajo en la blacklist de `xpcproxy`/exec,
hooks XPC, dyld e inyección, confianza, IPC, recuperación y pruebas reales.
El gate no debe activarse solo para permitir pulsar el botón.

La firma de CI es `ldid` ad hoc con entitlements privados heredados de
Dopamine, no una firma Apple de distribución. Su instalación depende de un
entorno compatible con tales firmas (por ejemplo TrollStore en versiones
compatibles). **No se garantiza apertura ni compatibilidad en un iPhone
concreto**. Para reducir el riesgo de interacción con el jailbreak existente,
usar solo hardware de pruebas y no instalar los paquetes `COMPILE-ONLY`.

El verificador `tools/verify_roothide_full_experimental.py` comprueba
recursos y hashes pinneados, `basebin.tar`, identidad distinta, formato Mach-O,
marcador compilado, CRC, rutas y ausencia de entradas ZIP duplicadas. Esto
no acredita el comportamiento del kernel, `launchd`, `dyld`, ni el resultado
de instalación del dispositivo.

### Compilación macOS (después de preparar dependencias)

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 gmake NIGHTLY=1
cp Application/Dopamine.ipa Application/RootHide3-Full-Experimental.ipa
python3 tools/verify_roothide_full_experimental.py --ipa Application/RootHide3-Full-Experimental.ipa --json
```

La variante stock se conserva intacta cuando
`ROOTHIDE_EXPERIMENTAL_BUILD` no está establecido. El port completo necesita
un ciclo posterior de pruebas controladas antes de permitir el jailbreak.
