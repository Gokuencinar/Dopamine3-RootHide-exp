# RootHide 3 — beta con instalación del jailbreak habilitada

Esta variante permite ejecutar los exploits de Dopamine e instalar y activar el
bootstrap oculto del port. No se ha probado en un dispositivo físico. La
compilación y los tests de host no prueban estabilidad de launchd, dyld,
ocultación, instalación de paquetes ni recuperación tras un fallo.

## Identidad y alcance

- Aplicación: **RootHide 3 Hardware Beta**.
- Bundle: `com.gokuencinar.roothide3.hardwarebeta`.
- `RH3_FULL_APP_EXPERIMENTAL=1`, `ROOTHIDE3_BOOTSTRAP_READY=1`.
- Solo arm64e con iOS 15/16 y una combinación de exploits disponible en Dopamine.
  No se amplía la compatibilidad de los exploits por activar esta variante.
- Se corrige el mínimo de carga de `Titan.framework` de 26.1 a 15.0 para
  alinearlo con la aplicación. Sus rangos de explotación del Info.plist se
  conservan. El verificador rechaza binarios embebidos con un mínimo superior
  al declarado por la app.
- Firma de ldid con los entitlements privados de Dopamine. Necesita un
  instalador compatible; una firma convencional puede perder permisos necesarios.

## Instalación y comprobaciones

1. Utilizar un dispositivo de pruebas y conservar una copia de los datos.
   Arrancar sin otro jailbreak activo. La beta rechaza `/var/jb`, contenedores
   ajenos de RootHide y estados incompletos; no los elimina ni los convierte.
2. Instalar la IPA identificada como **Hardware Beta**. Abrirla y revisar que el
   modelo/iOS sean los esperados. Elegir el gestor de paquetes y pulsar jailbreak.
3. Antes del workaround de memoria y de los exploits se comprueban arquitectura,
   iOS, disponibilidad de exploits, estado del bootstrap y recursos fijados por
   hash. Si se rechaza la prueba, se muestra el motivo y se permite cerrar.
4. La instalación usa sus propios contenedores `.jbroot-*`, comprueba los
   paquetes RootHide y evita instalar las dependencias convencionales en `/var/jb`.
   La inyección en launchd tiene plazos de espera y exige el handshake.
   Los comandos internos usan el helper de spawn de RootHide solo con un
   contenedor oculto activo. El parcheo de hijos permanece desactivado hasta
   preparar launchd/dyld; los fallos posteriores terminan y recogen al hijo
   conocido, con espera acotada, y restauran los flags de spawn del llamante.
5. La activación experimental fuerza inicialmente el modo sin tweaks mediante
   `.safe_mode`. No instalar tweaks antes de comprobar arranque, gestor de
   paquetes, rutas del bootstrap y reinicio. Cada nueva inyección desde esta beta
   vuelve a imponer esa base sin tweaks; no es una validación de la inyección de tweaks.
6. La preparación del bootstrap se ejecuta con `sh -e`. Un comando fallido
   impide registrar éxito. Se conservan los marcadores y backups de transacciones
   interrumpidas para su diagnóstico, sin repetir automáticamente scripts parciales.

## Si falla

Conservar el mensaje completo, los logs exportados por la app, la build exacta,
el modelo y la versión/build de iOS. No repetir intentos tras un timeout de
inyección, una instalación interrumpida o un crash nuevo. Un fallo después de
inyectar launchd puede haber producido efectos aunque la app muestre un error.

Un reinicio completo puede devolver el dispositivo al estado sin jailbreak,
pero no elimina los archivos del bootstrap y no se ha validado como recuperación
de todos los fallos de este port. No borrar manualmente todos los `.jbroot-*` ni
usar la desinstalación de otro jailbreak contra estos contenedores.

La opción de eliminación de esta app utiliza el camino de RootHide 3 y verifica
la propiedad de ambos contenedores. Solo debe intentarse cuando el entorno esté
operativo; su funcionamiento real tampoco se ha probado. Los marcadores de
recuperación impiden eliminar estados ambiguos y pueden exigir recuperación manual.
La beta permite además el helper root de eliminación tras reiniciar sin jailbreak;
este devuelve error real si no puede verificar o eliminar su propio bootstrap.

## Generar la variante

En GitHub Actions, ejecutar manualmente **Dopamine: build and upload** sobre la
rama del port con `hardware_beta=true`. Los pushes normales y las PR siguen
generando la variante protegida con jailbreak desactivado.

El artefacto es `RootHide3-HARDWARE-BETA-JAILBREAK-ENABLED`, con la IPA, su hash
SHA-256 y el informe de inspección. La auditoría estricta final sigue rechazando
una publicación como jailbreak verificado mientras no existan pruebas reales.

En macOS con las dependencias preparadas:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 ROOTHIDE_HARDWARE_TEST=YES gmake NIGHTLY=1
cp Application/Dopamine.ipa Application/RootHide3-Hardware-Beta.ipa
python3 tools/verify_roothide_full_experimental.py --hardware-beta --ipa Application/RootHide3-Hardware-Beta.ipa --json
```
