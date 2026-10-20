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

## Si falla

Guarda el mensaje de error, los logs, el modelo, la versión exacta de iOS y la revisión de la app. No repitas el proceso sin revisar el fallo: puede haber quedado un bootstrap a medias. No se borra automáticamente una instalación de RootHide 2, y reiniciar no garantiza resolver cualquier estado parcial.

## Compilar esta variante

Los builds normales mantienen el jailbreak desactivado. La variante habilitada se genera manualmente con `hardware_beta` en GitHub Actions o, en macOS con las dependencias del proyecto:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 ROOTHIDE_HARDWARE_TEST=YES gmake NIGHTLY=1
python3 tools/verify_roothide_full_experimental.py --hardware-beta --ipa Application/Dopamine.ipa --json
```

El identificador de esta app es `com.gokuencinar.roothide3.hardwarebeta`. Compilar y revisar el paquete no sustituye las [pruebas en un iPhone](validation/README.md).
