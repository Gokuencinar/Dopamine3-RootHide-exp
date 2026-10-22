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

## Contraseña de mobile (diagnóstico posterior a r134)

En la prueba del iPhone X con r134, `pw usermod 501 -h 0` devolvió dos veces el código 67 tras completarse la autenticación y el parcheo del proceso. En `sysexits`, 67 corresponde a `EX_NOUSER`; los archivos `etc/master.passwd` de los dos bootstraps fijados sí contienen `mobile` con UID 501. La corrección del código utiliza el nombre `mobile` y `pw -V <hidden-root>/etc` para apuntar explícitamente a la base privada; verifica su ubicación, propietario, estado anterior y cambio real del hash. No se ha validado todavía el cambio en hardware.

## SSH y visualización del interruptor de tweaks en r140

La comprobación de Windows establece conexión TCP con el puerto 22 pero recibe
`Connection reset` **antes del banner SSH**, sin enviar contraseña. La
existencia de un listener puede corresponder a un socket de `launchd` aun si
el daemon que debe atender la conexión no consigue ejecutarse. No se considera
comprobado que `sshd` esté activo ni que haya un problema de contraseña.

El registro de hardware r140 tenía `tweak_safe_mode=1` y
`tweak_loader_present=1`, pero el usuario indicó que la interfaz mostraba la
inyección activada. La lectura anterior del interruptor consultaba
`fileExistsAtPath` desde el sandbox de la app, con posible falso negativo.
Ahora consulta **como root temporal** el marcador de su bootstrap verificado y
muestra desactivado si no consigue leerlo de forma fiable. La comprobación
pasiva de SSH incorpora presencia de configuración, número de claves de host
y si el ejecutable declarado por el plist está accesible y vive dentro del
bootstrap oculto, sin revelar rutas ni contenido de claves. No cambia el
estado de `sshd`, las claves, las cuentas ni la instalación.

**Nunca introduzcas tu contraseña en un log, issue o mensaje de diagnóstico.** Si una prueba devuelve error, no reintentes el cambio repetidamente ni edites a mano `master.passwd`/`spwd.db`. Comparte únicamente las etapas y códigos numéricos del diagnóstico.

## Inyección después de repetir Jailbreak, NewTerm y SSH

La prueba en hardware posterior a r138 observó que los tweaks podían funcionar
solo después de actualizar las aplicaciones y reiniciar el espacio de usuario.
Se ha corregido el comportamiento que **recreaba forzosamente**
`basebin/.safe_mode` en cada nuevo intento de jailbreak, aunque el bootstrap
ya estuviera instalado. En la primera activación se sigue forzando el modo
seguro; a partir de entonces se conserva la elección registrada del usuario.
El botón de inyección comprueba ahora el resultado de modificar el marcador y
no ofrece un reinicio si la operación falla.

La opción **Ajustes → Diagnosticar tweaks, NewTerm y SSH** es de solo lectura:
registra si existen el marcador de modo seguro, TweakLoader, el bundle NewTerm,
el ejecutable sshd y plists SSH del root verificado. No almacena las rutas
privadas completas, no cambia contraseñas ni inicia servidores. **Encontrar un
plist o binario no demuestra que el daemon esté en ejecución.** Para un fallo de
NewTerm hace falta además el informe de cierre o el mensaje en pantalla; para
SSH, distinguir «conexión rechazada», «tiempo agotado» y «autenticación fallida».
El registro de apps no se ejecuta automáticamente durante el primer arranque
porque una versión anterior se bloqueaba en el primer hijo parcheado.

## Diagnóstico y preparación segura de SSH y tweaks (candidata posterior a r146)

En r143, `tweak_safe_mode=1` seguía bloqueando TweakLoader pese a que la
interfaz indicaba la inyección activada. Además de la lectura privilegiada, se
elimina otra recreación del marcador basada en una preferencia obsoleta durante
la fase de jailbreak. La primera instalación sigue activando modo seguro y
el watchdog puede volver a activarlo tras un panic; no se desactiva el modo
seguro de forma automática cuando hay señales de fallo.

Tras habilitar **Ajustes → Inyección de tweaks** y realizar **un** reinicio
de espacio de usuario, pulsa **Verificar carga real de tweaks**. Esta acción
ejecuta `rh3tweakprobe`, un binario efímero del BaseBin firmado en CI. Solo
da éxito si se ejecutó `systemhook` en ese proceso y `dlopen` abrió
`TweakLoader.dylib` realmente. No prueba por sí sola que un tweak específico
de SpringBoard funcione; si falla, comparte el resultado y el registro, sin
repetir reinicios.

La distribución inicial RootHide **no contiene OpenSSH**; su
`us.diatr.shshd.plist` sirve blobs SHSH y no es un servidor SSH. El OpenSSH
instalado posteriormente tenía `ssh_host_key_files=0`, ejecutable SSH
presente y un programa del plist no accesible desde launchd. Con el jailbreak
activo, y **solo tras asegurar contraseñas de acceso no predeterminadas**, pulsa
**Ajustes → Preparar OpenSSH en RootHide**. La operación valida el bootstrap
oculto, busca una única entrada `com.openssh.sshd` con socket, genera únicamente
su clave de host ED25519 bajo `<hidden-root>/etc/ssh` si falta, y ejecuta
`sshd -t` con rutas explícitas. No inicia servicios, no toca la instalación
stock de iOS ni reescribe plists de paquetes. Tras un reinicio de espacio de
usuario, el hook de launchd reubica **solo** `com.openssh.sshd` a rutas del
bootstrap activo en su diccionario XPC, incluso cuando cambia el nombre
aleatorio de la raíz. No redirige ni altera `us.diatr.shshd`.

Prueba desde el ordenador con `ssh -vvv -o BatchMode=yes mobile@IP`
primero, sin enviar contraseña. Se espera recibir un banner de servidor
`SSH-2.0` y negociar claves; TCP puerto 22 abierto no basta. No compartas
credenciales ni material de host key. Ante cualquier fallo de prueba física,
detente y comparte código de error y línea `runtime:`; no reinstales
el bootstrap ni cambies permisos de `/etc` o `/usr` del sistema.

## Si falla

### Diagnóstico puntual de activación OpenSSH (r161)

Si «Preparar OpenSSH» termina bien y el registro contiene
`BOOT pid=1 OpenSSH import: socket XPC program arguments rebased to active hidden root`,
pero el puerto 22 sigue cerrando la conexión antes de `SSH-2.0`, usa
**Ajustes → Diagnosticar arranque de OpenSSH (solo lectura)**. Esta acción
consulta el `com.openssh.sshd` real mediante el `launchctl print` del
bootstrap oculto y revisa, sin modificarlos, los campos `Sockets` e
`inetdCompatibility.Wait` del plist.

Solo se guardan en el diagnóstico los estados normalizados, códigos y
contadores. Se descarta la salida íntegra de `launchctl`: nunca se
comparten rutas privadas, variables de entorno ni contenido de claves.
La captura tiene límite de tamaño y plazo, y solo puede terminar su propio
proceso de consulta. No conecta al puerto 22, no habilita, reinicia ni
detiene SSH y no necesita un reinicio de espacio de usuario. Una respuesta
`state=waiting` puede ser normal en servicios activados por socket.

Comparte el registro de RootHide después de ejecutar la opción una sola
vez; distingue el código del comando `launchctl` del último código de
salida registrado por `launchd` para `sshd`. No reinstales OpenSSH ni
repitas «Preparar OpenSSH» mientras se investiga el arranque.

### Precisión diagnóstica posterior a r161 (candidata r162)

En la prueba r161, los puertos TCP 22 y 2222 aceptan la conexión desde
Windows, pero ambos cierran sin banner y `launchctl print` aún indica
`runs=0`. El plist de OpenSSH de Procursus puede nombrar los sockets
`SSHListener` y `SSHListener2`, de modo que el antiguo indicador
`listeners=0` no diagnosticaba su ausencia. El indicador anterior
`program_rooted=0` era también una coincidencia textual estricta que
podía confundir alias de ruta con un ejecutable fuera del bootstrap.

La nueva consulta mantiene el comportamiento de **solo lectura**, pero
cuenta los servicios de puerto 22 y 2222 presentes *en el plist en disco*,
registra `Disabled` del plist como `-1/0/1` (`-1` significa ausente) y
clasifica por categorías fijas las rutas `path` y `program` que reporta el
servicio efectivo mediante `launchctl print`. También informa únicamente
si la representación humana contiene los argumentos de configuración y
clave del bootstrap activo. No imprime rutas, datos de sockets, salida
cruda de `launchctl`, variables de entorno ni secretos. No demuestra por
sí sola qué proceso acepta las conexiones entrantes.

Con r162 instalada, basta ejecutar una sola vez **Diagnosticar arranque de
OpenSSH (solo lectura)** y compartir el nuevo registro. No preparar SSH,
alterar claves, forzar `launchctl kickstart` ni reiniciar.

Guarda el mensaje de error, los logs, el modelo, la versión exacta de iOS y la revisión de la app. No repitas el proceso sin revisar el fallo: puede haber quedado un bootstrap a medias. No se borra automáticamente una instalación de RootHide 2, y reiniciar no garantiza resolver cualquier estado parcial.

## Compilar esta variante

Los builds normales mantienen el jailbreak desactivado. La variante habilitada se genera manualmente con `hardware_beta` en GitHub Actions o, en macOS con las dependencias del proyecto:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 ROOTHIDE_HARDWARE_TEST=YES gmake NIGHTLY=1
python3 tools/verify_roothide_full_experimental.py --hardware-beta --ipa Application/Dopamine.ipa --json
```

El identificador de esta app es `com.gokuencinar.roothide3.hardwarebeta`. Compilar y revisar el paquete no sustituye las [pruebas en un iPhone](validation/README.md).
