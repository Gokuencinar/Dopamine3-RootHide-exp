# Probar la beta

Esta variante tiene habilitado el intento de jailbreak. Aún no hay pruebas en un iPhone, así que se publica como pre-release.

En iOS 18 admite A12/A13 hasta 18.7.1. También permite arm64e con iOS 15/16 si hay exploits compatibles. Consulta [los límites de iOS 18](IOS18-SIDELOADING.md) antes de instalarla.

## Instalación

1. Haz una copia de tus datos y usa un iPhone de pruebas, sin otro jailbreak o bootstrap instalado.
2. Descarga la IPA de [Releases](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/releases).
3. Refírmala con AltStore u otro instalador compatible. La IPA lleva firma ad hoc; todavía no se ha probado la instalación con estos servicios.
4. Abre la app y comprueba la compatibilidad antes de pulsar Jailbreak.

Cada intento empieza sin tweaks. Si termina bien, puedes solicitar la inyección desde los ajustes de la app y reiniciar el espacio de usuario. Ese paso tampoco está probado en hardware.

La instalación inicial incluye RootHide Manager y los gestores que selecciones: Sileo y, opcionalmente, Zebra. No incluye arm64ePatcher.

## Si falla

Guarda el mensaje de error, los logs, el modelo, la versión exacta de iOS y la revisión de la app. No repitas el proceso sin revisar el fallo: puede haber quedado un bootstrap a medias. No se borra automáticamente una instalación de RootHide 2, y reiniciar no garantiza resolver cualquier estado parcial.

## Compilar esta variante

Los builds normales mantienen el jailbreak desactivado. La variante habilitada se genera manualmente con `hardware_beta` en GitHub Actions o, en macOS con las dependencias del proyecto:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 ROOTHIDE_HARDWARE_TEST=YES gmake NIGHTLY=1
python3 tools/verify_roothide_full_experimental.py --hardware-beta --ipa Application/Dopamine.ipa --json
```

El identificador de esta app es `com.gokuencinar.roothide3.hardwarebeta`. Compilar y revisar el paquete no sustituye las [pruebas en un iPhone](validation/README.md).
