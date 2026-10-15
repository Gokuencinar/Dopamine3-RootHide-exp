# Variantes de la app

Hay tres paquetes distintos. Para probar el intento de jailbreak necesitas la Hardware Beta.

| Variante | Qué permite |
| --- | --- |
| Device Test | Instalar y abrir una app de diagnóstico, sin código de jailbreak. |
| Full Experimental | Revisar la app completa y sus componentes, con el jailbreak desactivado. |
| Hardware Beta | Intentar instalar el jailbreak y el port de RootHide. Sin pruebas en un iPhone todavía. |

La Full Experimental usa `com.gokuencinar.roothide3.fulltest`. El bloqueo de RootHide sigue activo y no se continúa con el bootstrap normal de Dopamine como alternativa.

En macOS, con las dependencias preparadas:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 gmake NIGHTLY=1
python3 tools/verify_roothide_full_experimental.py --ipa Application/Dopamine.ipa --json
```

`NIGHTLY=1` por sí solo no habilita el jailbreak. Para la variante habilitada consulta [HARDWARE-BETA.md](HARDWARE-BETA.md). Todos los paquetes necesitan una firma válida para instalarlos; la instalación en un dispositivo sigue pendiente de probar.
