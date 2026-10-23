# Probar la beta

Esta variante tiene habilitado el intento de jailbreak. La revisión d297586 (r134.a1) llegó en un iPhone X, iOS 16.7.15, hasta jailbreakd autenticado, y el usuario confirmó que Sileo y RootHide Manager abren después de «Actualizar aplicaciones del jailbreak». Zebra todavía se cierra y Sileo detectó la dependencia libkrw0-plugin ausente. Esto es evidencia parcial de hardware, no validación de todo el jailbreak; los cambios posteriores siguen sin probarse físicamente.

La nueva candidata elimina el filtro de CPU arm64e y contempla iOS 15, 16, 17, 18 y 26. La combinación de exploits de Dopamine decide qué dispositivo y versión pueden continuar. Consulta la [tabla de compatibilidad](README.md#compatibilidad). La primera release mantiene los límites anteriores.

## Instalación

1. Haz una copia de tus datos y usa un iPhone de pruebas, sin otro jailbreak o bootstrap instalado.
2. Descarga la IPA de [Releases](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/releases).
3. Refírmala con AltStore u otro instalador compatible. La IPA lleva firma ad hoc; todavía no se ha probado la instalación con estos servicios.
4. Abre la app y comprueba la compatibilidad antes de pulsar Jailbreak.

La primera instalación empieza sin tweaks. En posteriores activaciones se conserva el modo seguro efectivo; el cambio de inyección puede requerir una nueva fase de jailbreak con permisos de instalación. No interpretes una solicitud pendiente como activación efectiva. Este flujo nuevo tampoco está probado en hardware.

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
**Ajustes → Reparar OpenSSH en RootHide (con respaldo)**. La operación valida el bootstrap
oculto, busca una única entrada `com.openssh.sshd` con socket, genera únicamente
su clave de host ED25519 bajo `<hidden-root>/etc/ssh` si falta, y ejecuta
`sshd -t` con rutas explícitas. Desde la revisión posterior a r165, una vez
validada la configuración, guarda **una copia privada de los bytes originales**
del único plist `com.openssh.sshd` y cambia atómicamente **solo** `Program`
y `ProgramArguments` para invocar `sshd -i -f <config> -h <clave>` bajo la
raíz oculta activa. Conserva `Sockets`, `inetdCompatibility`, `Disabled` y
el resto de propiedades. No inicia servicios ni toca la instalación stock de
iOS, otras claves o `us.diatr.shshd`. El cambio en disco **no** cambia la
configuración del servicio ya cargada: solo se observará después de una nueva
importación de `launchd` mediante un reinicio de espacio de usuario **manual
y controlado**. Detenerse si la función informa error; no repetir reinicios.

**Advertencia de persistencia:** RootHide vuelve a aleatorizar el nombre de
la raíz durante un jailbreak completo posterior. Las rutas absolutas
persistidas podrían caducar después de ese cambio; antes de volver a probar
OpenSSH en otra sesión de jailbreak hay que comprobar la ruta con el botón de
diagnóstico y, si procede, repetir la reparación optativa. No se instala
ningún hook global nuevo en PID 1 para evitar riesgos de arranque.

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

### Diferencial posterior a r164: sin tocar OpenSSH

El registro r164 (22/10/2026 04:28:30 UTC) obtuvo
`origin_class=expected program_class=other_absolute runs=0`, con ambas
entradas de socket presentes y sin las rutas de configuración/clave esperadas
en la representación humana de `launchctl`. Esto demuestra una discrepancia
entre el ejecutable *esperado* por el hook y el programa *declarado* en el
trabajo activo; no demuestra por sí solo qué ruta se está ejecutando, que el
hook se haya aplicado al trabajo efectivo ni si hay un override de
habilitación.

La siguiente instrumentación, siempre bajo el mismo botón **de solo lectura**,
añade exclusivamente:

- `disk_program_class`: categoría fija de `Program` en el plist instalado.
- `program_matches_plist=-1/0/1`: imposible de comparar / distinto /
  equivalente tras normalizar alias. Solo compara rutas internamente.
- `disabled_override=disabled|enabled|no_override|unknown`: resultado de
  consultar `launchctl print-disabled system`, limitado a la etiqueta exacta
  `com.openssh.sshd` y admitiendo variantes `true/false` o
  `disabled/enabled`. `unknown` incluye formatos desconocidos, error,
  truncado, timeout o consulta no compatible.

No se exportan rutas, otras etiquetas del dominio, argumentos completos,
credenciales ni claves. Ninguna de las dos consultas inicia, habilita,
reinicia o detiene SSH. El estado `no_override` tampoco prueba un daemon
activo; ha de cotejarse con `Disabled` del plist y los datos de `launchctl`.
Hasta que esta evidencia discrimine la causa, no parchear globalmente
`launchd`, no reescribir el plist de terceros ni regenerar host keys.

### Diagnóstico r165 y reparación optativa posterior

El registro r165 (05:14 UTC del 22/10/2026) confirmó
`program_matches_plist=1 disk_program_class=other_absolute disabled_override=enabled`.
Es decir, el trabajo de `launchd` preserva el ejecutable original del plist,
a pesar de que la transformación XPC del hook sí se registró en el inicio.
El servicio no está deshabilitado. Se descarta ampliar el hook a todo
`xpc_create_from_plist` en PID 1: afecta a importaciones no relacionadas y
no hay pruebas de que sea la ruta efectiva. En su lugar, una acción **con
confirmación expresa** reubica únicamente ese plist y conserva un respaldo
privado en `.com.openssh.sshd.rh3-original` (sin sufijo `.plist`, no importable
por el hook). No se hace `bootout`, `kickstart`, ni reinicio implícito.
La prueba física pendiente es comprobar después de una nueva importación que
`program_class=expected`, los argumentos `-f/-h` aparecen y la conexión
recibe el banner `SSH-2.0` antes de enviar credenciales. El éxito de la
escritura del plist **no es** prueba de SSH funcional.

### r166: rechazo EPERM de la reparación; diagnóstico r167

El log r166 del 22/10/2026 a las 06:24:43 UTC registra
`SSH preflight: verified; key_generation_needed=0`,
`RootHide child sshd: ... result=0` y
`socket job atomic rebase result=1 changed=0`. Significa `EPERM` antes
de completar el reemplazo atómico del plist; no es un error demostrado de
`sshd` ni de su clave. El código r166 no distingue la comprobación concreta
fallida: UID/GID, permisos del plist/directorio, hardlinks, estado de respaldo,
o permisos devueltos por `openat`, `fchown`, `fchmod` y `fsync`.

La revisión r167 amplía la acción **Diagnosticar arranque de OpenSSH
(solo lectura)** con un resumen de metadatos: `directory_trusted`,
`original_group_trusted`, `original_mode_trusted`,
`original_links_trusted`, `backup_state` (0 ausente, 1 metadatos
correctos, 2 metadatos sospechosos, −1 desconocido). No registra valores de
propietario, rutas ni contenido de los ficheros. La reparación optativa,
si se ejecuta en un ensayo posterior, informa `stage=<etapa_fija>` junto
al código de error. Se mantienen sin cambios todas las comprobaciones
de seguridad y no se modifica ningún plist con la acción diagnóstica.

**Hasta conocer esos datos:** no reiniciar espacio de usuario, no volver
a ejecutar el jailbreak, no cambiar permisos de SSH manualmente ni repetir
la reparación a ciegas. `changed=0` no demuestra que no exista algún
respaldo parcial de un intento previo; `backup_state` ayudará a comprobarlo.

### r167: `create_backup` denegado — comprobación r168 de acceso instalador

En el log del 22/10/2026 a las 18:34:45 UTC la comprobación
`atomic rebase result=1 changed=0 stage=create_backup` identifica el
`openat(O_CREAT|O_EXCL|O_NOFOLLOW)` del respaldo en la carpeta de daemons.
El análisis anterior del mismo dispositivo mostró directorio y plist
correctamente poseídos, sin enlaces extraños y sin respaldo previo. No falló
`fchown`, `fchmod` o `renameat`: esas operaciones nunca se alcanzaron.
La raíz primaria está situada dentro de `/var/containers/Bundle/Application`,
que tiene restricciones adicionales de escritura en iOS; UID 0 y quitar
Seatbelt no garantizan acceso de instalación.

El método de arranque del jailbreak activa `CS_INSTALLER` durante la
explotación; la llamada privilegiada posterior desde la app no verifica
ese flag. La revisión r168 añade **solo lectura** a la misma acción de
diagnóstico: `SSH socket creation policy: csops_ok=... app_installer=...
app_platform=... directory_owner_write=... directory_immutable=...
mount_writable=...`. Son campos numéricos, sin rutas, ID de procesos o
secretos. Si `app_installer=0`, el permiso instalador ausente será la
hipótesis principal; no se elevará el flag automáticamente. Si vale 1,
se seguirá investigando el control de acceso del contenedor. No mover
el respaldo a AppGroup como arreglo aislado: el destino y el rename
siguen estando protegidos. No repetir la reparación a ciegas.

Guarda el mensaje de error, los logs, el modelo, la versión exacta de iOS y la revisión de la app. No repitas el proceso sin revisar el fallo: puede haber quedado un bootstrap a medias. No se borra automáticamente una instalación de RootHide 2, y reiniciar no garantiza resolver cualquier estado parcial.

## Compilar esta variante

### Propuesta integrada de recuperación SSH (rama `fix/roothide3-ssh-preboot-installer-rc`)

Esta rama surge del análisis del error físico r167 `stage=create_backup,
result=1, changed=0`. La operación fallaba creando un fichero dentro del
bootstrap primario, situado bajo el contenedor protegido
`Bundle/Application`. Los metadatos del directorio y del plist eran
correctos, la clave de host ya existía y `sshd -t` terminó con código 0.
No se ha demostrado en hardware que la nueva estrategia recupere SSH.

En RootHide 2 (pin `e8de6e5`) el proceso instalador recibe autorización
especial durante el exploit y la aplicación puede volver a disponer de
ella al arrancar. El nuevo enfoque **no** otorga esa autorización a la
aplicación de forma permanente ni introduce endpoints XPC para cambiar
los permisos de otros procesos. Únicamente utiliza la autorización ya
comprobada durante la propia fase de jailbreak:

- El usuario habilita voluntariamente **Preparar OpenSSH al iniciar jailbreak
  (optativo)** tras cambiar sus contraseñas. Es una preferencia persistente
  y reversible; pulsarla no modifica ficheros ni arranca servicios.
- Tras re-aleatorizar la raíz e instalar los paquetes del bootstrap,
  pero antes del siguiente reboot de espacio de usuario, la app verifica
  `CS_INSTALLER`, `CS_PLATFORM_BINARY`, UID/GID 0 y la identidad de RootHide
  comparando la raíz instalada con `gSystemInfo.jailbreakInfo.rootPath`,
  que se actualiza tras su rotación. No realiza consultas XPC adicionales a
  PID 1 en la fase crítica. La reparación manual sí obtiene la ruta actual
  por XPC, en vez de usar la caché `jbclient_get_jbroot()`.
- La preparación automática **exige una clave ED25519 existente**; no genera,
  rota ni sobrescribe claves. Comprueba tipos, propiedad, permisos, rutas y
  contenido estructural del único job; no ejecuta `sshd -t` en la fase crítica,
  ya que su `posix_spawn`/patch-child XPC no tienen plazo síncrono real y
  podrían bloquear todo el jailbreak. `sshd -t` sí continúa en la acción
  manual, y pasó físicamente en r166/r167; esto **no prueba** una futura
  configuración distinta. La reparación manual conserva su opción confirmada
  para generar una clave faltante.
- La transacción construye primero un respaldo en nombre aleatorio y lo
  publica por `renameatx_np(RENAME_EXCL)` tras validarlo, sin pisar jamás uno
  preexistente. Si esa primitiva no se admite, falla sin sustituir el plist.
  Después crea un enlace temporal al inode original antes de `renameat` y comprueba de
  nuevo datos, permisos, ctime/mtime e inode para detectar cambios del gestor
  de paquetes. Si falla tras sustituir el plist, intenta restaurar el inode
  original **solo si el plist vivo todavía es el reemplazo propio**. Los
  errores de recuperación quedan registrados. Si un corte deja un hardlink de
  recuperación, se elimina únicamente si está demostrado que apunta al mismo
  inode original o que el nuevo job coincide exactamente en las propiedades
  no modificadas. Si no puede demostrarse, se conserva y el cambio se rechaza.
  No se afirma rollback absoluto frente a cortes de energía o una escritura
  simultánea de dpkg.
- En lugar de descartar ACL, atributos extendidos o flags del plist, la RC
  rechaza el cambio con seguridad si encuentra metadatos especiales que no
  puede preservar. Conserva los `Sockets`/`inetdCompatibility`, valores de
  servicio y demás claves, modificando únicamente `Program` y
  `ProgramArguments`.
- Un error de OpenSSH se registra como opcional y **no aborta** el arranque
  del jailbreak. La reparación inmediata desde una app reabierta se niega
  sin escribir si ya no existe la autorización instalador.
- La preferencia permanece activa para actualizar las tres rutas
  absolutas cada vez que se re-aleatorice la raíz en una nueva sesión.

La configuración cargada de `launchd` no cambia hasta una importación
posterior: actualizar el plist no demuestra que el servicio arranque. Además,
RootHide3 hoy ofrece **dos rutas** de importación de `/Library/LaunchDaemons`
(diccionario XPC y `Paths` en disco); r165 demostró que la primera reescritura
XPC no gobernó el job efectivo. Escribir antes de un userspace reboot debería
alinear ambas, pero **todavía no se ha probado en hardware** ni se conoce la
fuente definitiva de importación del job.

**Auditoría adicional del spawn de OpenSSH (22/10/2026, sin iPhone):** el
donante RootHide 2 (`BaseBin/launchdhook/src/roothider.m:212-275`) suspende y
parchea los hijos de PID 1 mediante `jbdSpawnPatchChild`, fuerza
`DYLD_IN_CACHE=0` cuando inyecta una dylib y contempla confianza recursiva.
RootHide3 (`BaseBin/systemhook/src/common/common.c:392,445-470`) excluye PID 1
del camino `rh3_spawn_patched` y de ese cambio de dyld, mientras su
`launchdhook/src/spawn_hook.c:345` confía inicialmente solo en el ejecutable.
Esta **diferencia de implementación es real**, pero no demuestra que el
`sshd` concreto falle por ella. Si `launchd` lo inicia a través de
`/usr/libexec/xpcproxy`, el proxy sí puede recibir `systemhook`, realizar su
check-in alternativo en iOS 16 (`systemhook/src/main.c:423-438`) y pasar por
el camino RootHide con confianza recursiva y parcheo al hacer el `execve`
(`systemhook/src/main.c:284-323`). No consta todavía cuál de esas dos rutas
usó efectivamente el trabajo `com.openssh.sshd`.

**Decisión de seguridad:** no transportar a ciegas el patch-child de RootHide
2 a PID 1. La ruta `jbclient_roothide_patch_child` depende de servicios XPC
que pueden convertirse en una llamada autorreferente desde `launchd`; la vía
directa a `jailbreakd` también usa una petición síncrona sin límite estricto
de tiempo. Antes de cualquier cambio que afecte al spawn, se necesita
evidencia del ejecutable cargado, secuencia xpcproxy/directa, resultado del
check-in, confianza de dependencias y estado del proceso hijo. Ninguna de las
dos rutas ha sido verificada en un nuevo ensayo físico.

Tampoco debe ofrecerse como arreglo «inofensivo» confiar recursivamente el
sshd desde la app durante preboot: la implementación RootHide
(`libjailbreak/src/roothider/signatures.m:377-385` y `recdhash.m:221-244`)
puede randomizar hashes y **reescribir contenido Mach-O** del ejecutable y
dependencias, además de crear enlaces bajo jbroot. Esa ruta necesitaría una
transacción específica para binarios de paquetes y una política de IPC con
tiempo máximo verificable; la RC actual deliberadamente NO la ejecuta.

**Comparación con Relaxin (fuente pública de OwnGoal Studio, pin
`owngoal-dev/Relaxin@f44e0acfe`, 17/08/2026):** el repositorio está archivado
y constituye una instantánea antigua; **no contiene** las modificaciones de
las versiones 0.5.5/0.5.6 anunciadas después. No confundir la web
`relaxin.dev`, que es un archivo mantenido por terceros, con el repositorio
oficial ni considerar su IPA una reparación de esta instalación.

- `Vendor/Dopamine/BaseBin/launchdhook/src/daemon_hook.m:33-53` incorpora
  `/basebin/LaunchDaemons` tanto a `LaunchDaemons` como a `Paths`, pero NO
  incorpora `/Library/LaunchDaemons` por ninguna de esas dos vías. En cambio,
  `Vendor/Dopamine/BaseBin/jbctl/src/internal.m:297-300` realiza **después de
  disponer de launchdhook y systemhook** el `launchctl bootstrap system
  /Library/LaunchDaemons`. Es la misma separación intencional que el donor
  RootHide 2 pinned, distinta de la doble importación inicial RootHide3.
  Este contraste **no demuestra** aún si eliminar uno de los importadores
  RootHide3 mantendría operativos los demás daemons en el iPhone; aplazar
  una migración global del orden de arranque hasta tener evidencia.
- `Vendor/Dopamine/BaseBin/launchdhook/src/roothider.m:194-252` mantiene
  confianza recursiva, `DYLD_IN_CACHE=0` al inyectar y suspender/parchear los
  hijos de PID 1. Confirma que el diseño existe fuera del donor RH2, pero
  conserva `jbdSpawnPatchChild` **síncrono**, sin plazo estricto; no copiarlo
  al `launchd` experimental a ciegas. El camino de `xpcproxy`/`execve` de
  RootHide3 puede cubrir parte de la funcionalidad y sigue sin traza física.
- `Vendor/Dopamine/BaseBin/launchdhook/src/jbserver/jbdomain_systemwide.c:
  528-540` establece `CS_PLATFORM_BINARY` y `CS_INSTALLER` durante su entrega
  de privilegios. Es otra solución al problema de permisos, pero ampliar
  permanentemente los derechos de la app relanzada contradiría el principio
  de **privilegio temporal y mínimo** elegido aquí. Se conserva la ventana
  post-exploit con consentimiento específico en lugar de copiar ese patrón.

**Resultado de la comparación:** Relaxin aporta una confirmación independiente
de la separación de importadores y de la relevancia de trust/dyld en spawn,
pero su instantánea abierta NO contiene una corrección específica de
`com.openssh.sshd`, respaldo de su plist ni demostración de banner SSH para
este iPhone X. Nuestra corrección mantiene la preferencia opt-in y evita
añadir hooks globales o una petición XPC bloqueante a PID 1.
La aceptación física de esta RC exige `atomic rebase result=0`, un
`launchctl print system/com.openssh.sshd` con la ruta activa y los
argumentos esperados, y una conexión real que devuelva `SSH-2.0`
en el puerto previsto (sin autenticar). También deben seguir funcionando
Sileo, Zebra, el marcador de modo seguro, NewTerm según su diagnóstico
independiente y el reinicio de espacio de usuario.

**Limitaciones y condición de bloqueo:** `CS_INSTALLER` comprobado no garantiza
que el kernel permita `openat`, `renameatx_np`, `linkat` y `renameat` en el directorio Bundle
protegido. Para reducir la posibilidad de bloqueo la nueva ruta automática no
invoca `rh3RunCommand`, `sshd -t`, consultas XPC nuevas ni el helper general
de escalada. La
ejecución del servidor SSH y la sintaxis de una configuración alterada después
de los ensayos r166/r167 siguen pendientes de validación. Los nombres de
`.rh3-next-*` y `.rh3-original-next-*` abandonados llevan sufijo aleatorio,
no son importables por launchd ni se eliminan a ciegas; el backup publicado
conocido se valida estrictamente antes de reusarse.

**Estado:** trabajo local sin IPA aprobada. La suite Python es mayoritariamente
de contrato de fuente; no constituye compilación ObjC iOS, pruebas de fallos
de filesystem ni validación física. No instalar ni ejecutar otro jailbreak
basándose solamente en esta sección.

### Integración defensiva derivada de la IPA oficial Relaxin v0.5.6

Se contrastó el desensamblado verificado de la IPA oficial v0.5.6 con el
protocolo real de RootHide3: Relaxin prepara confianza con mensaje 1101,
finaliza trust de ejecución con 1102, conserva el watcher SETEXEC 1002/1003
y sigue parcheando hijos mediante 1001. **No** se trasplanta a PID 1: la
operación XPC continúa siendo síncrona, sin timeout/reentrancia demostrados,
y los dos `jailbreakd` no comparten el contrato de 1101/1102.

En su lugar, esta revisión corrige rutas comprobables de seguridad/arranque:

- Con host key ED25519 presente, el rebase opt-in de OpenSSH no requiere
  `ssh-keygen`; solo se verifica el generador antes de generar una clave en
  una acción interactiva expresamente autorizada. En preboot nunca genera.
  Antes de aceptar el binario se comprueba también que `usr` y `usr/sbin`
  sean directorios reales controlados por root (revalidación en commit),
  para no seguir symlinks intermedios de `lstat(sshd)`.
- La clasificación de procesos ignora entradas XPC no string de
  `ProcessBlacklist`, evitando una desreferencia de `NULL` en el hook
  compartido que también usa launchd.
- El hook **existente** de importación de `launchd` impide duplicados de
  `Paths` en lecturas sucesivas, comprueba respuestas XPC nulas y limita
  mapeos de plists a ficheros regulares de hasta 4 MiB. No incorpora nuevos
  endpoints, importadores ni privilegios.
- `jailbreakd` devuelve fallo si no consigue reanudar un hijo tras patch
  1001; el padre puede limpiar solamente el proceso que acaba de crear.
- El spawn compartido no intenta corregir la persona cuando el spawn falló;
  el watcher NOTE_EXEC tolera `EINTR`, y la limpieza de hijos suspendidos usa
  `waitpid(WNOHANG)` acotado en vez de una espera sin plazo.

Los tests de host ejecutan el clasificador real de blacklist y el helper de
consulta de `Paths` con dobles XPC, además de comprobar contratos de
propagación de error. Siguen sin simular APFS/launchd/iOS ni demostrar SSH.

**Riesgo residual a no ocultar:** entre la última validación del inode de
`com.openssh.sshd.plist` y `renameat` no existe una transacción CAS contra un
`dpkg` concurrente. Una actualización del paquete publicada precisamente en
ese intervalo podría sobrescribirse. El opt-in preboot sucede después de
finalizar el bootstrap; no se ha demostrado exclusión mutua con un gestor de
paquetes externo. No ejecutar la reparación interactiva durante operaciones
de paquetes; una futura variante solo debe ampliar el alcance tras demostrar
la seguridad del reemplazo en APFS. Tampoco está probado que el rebase se
importe efectivamente o que el banner SSH responda tras él.

Los builds normales mantienen el jailbreak desactivado. La variante habilitada se genera manualmente con `hardware_beta` en GitHub Actions o, en macOS con las dependencias del proyecto:

```sh
ROOTHIDE_EXPERIMENTAL_BUILD=1 ROOTHIDE_HARDWARE_TEST=YES gmake NIGHTLY=1
python3 tools/verify_roothide_full_experimental.py --hardware-beta --ipa Application/Dopamine.ipa --json
```

El identificador de esta app es `com.gokuencinar.roothide3.hardwarebeta`. Compilar y revisar el paquete no sustituye las [pruebas en un iPhone](validation/README.md).

### Candidata posterior a r172: correcciones de integridad y ciclo de vida

La r172 (`bce63b7`) compiló como Hardware Beta con jailbreak habilitado y
firmado ad hoc. Su `Build`, slices arm64/arm64e, empaquetado y publicación IPA
pasaron CI; el control estricto global sigue en 7/9 por el guard de fuente y
la ausencia de validación física, **no** por un error del compilador. Ningún
ensayo físico de esa IPA confirmó `SSH-2.0`, Sileo ni Zebra.

Esta revisión contiene correcciones verificables adicionales:

- **Repositorios de los gestores:** durante una reactivación de una instalación
  ya marcada como instalada, `prepareRootHideBootstrapWithCompletion:` ya no
  vuelve a llamar a `rh3BuildPackageSourcesInRoot`. Esa llamada repetida borraba
  `etc/apt/sources.list`, sobrescribía `default.sources` y reemplazaba la lista
  editable de Zebra. Las fuentes iniciales siguen preparándose al crear la
  raíz y al completar únicamente la recuperación verificada del choque `tmp`.
  No se reinstalan paquetes ni se refrescan iconos indiscriminadamente.
- **OpenSSH:** la transacción voluntaria de `com.openssh.sshd.plist` ancla
  `Library` y `LaunchDaemons` con directorios `O_NOFOLLOW`, modo y propietario
  validados antes de crear respaldos, impidiendo que una sustitución de
  `Library` por un enlace intermedio redirija la escritura a otro servicio.
  Mantiene la ventana original CS_INSTALLER y sus rechazos sin privilegios.
- **Importación launchd:** al inspeccionar plists importados de paquetes se
  evita bloquear PID 1 en ficheros especiales, se exige un diccionario de job
  con `Label`, y se libera el objeto XPC creado después de insertarlo (la
  inserción conserva su propia referencia). Reduce fugas por lecturas
  repetidas; no reescribe plists ni incorpora hooks nuevos.
- **SETEXEC:** cancelar una vigilancia `kevent` de un solo uso tolera `EINTR` y
  trata `ENOENT` como vigilancia ya consumida. Limpia el registro de usuario
  idempotentemente; otros fallos de kernel siguen propagándose sin éxito falso.
- **Comprobación adicional del paquete:** un verificador independiente exige
  `LC_CODE_SIGNATURE` válido a nivel estructural, `CodeDirectory` y
  entitlements XML exactamente iguales a la política fijada de Dopamine.
  Ejecuta pruebas de corrupción y casos negativos. **No** valida firma
  criptográfica CMS, un perfil Apple, aceptación de sideload ni ejecución iOS.

Se mantiene una limitación sustantiva: aunque la transacción del plist pase,
no se ha demostrado que la importación de `launchd` adopte la ruta corregida,
que el proceso `sshd` sobreviva a spawn/dyld ni que responda el banner. El
último `renameat` tampoco es un CAS frente a un `dpkg` concurrente. En
consecuencia, ni SSH ni los gestores deben declararse funcionales por los
tests de host o por una compilación nativa exitosa.

### Integración posterior a r172: solicitud explícita de tweaks y dyld acotado

Los registros físicos de r172 muestran `safe_mode=1` y que «Habilitar inyección»
devolvió `EPERM` (`result=1`). El bootstrap primario se conserva dentro de
`Bundle/Application` y deja de ser escribible cuando termina `CS_INSTALLER`.
La raíz secundaria `AppGroup/.jbroot-<jbrand>/var` permite guardar una petición
pendiente sin alterar el marcador protegido, ni declarar un reinicio como
solución de un cambio todavía no aplicado.

En esta revisión el interruptor crea o cancela una solicitud de una sola opción,
root-owned, `0600` y de contenido acotado, dentro de la secundaria enlazada al
root verificado. La interfaz devuelve el estado real y señala cuándo la
solicitud **sigue pendiente**. Únicamente la siguiente activación autorizada del
jailbreak, tras preparar el bootstrap y mientras la aplicación conserva
`CS_INSTALLER` y `CS_PLATFORM_BINARY`, puede aplicarla a `basebin/.safe_mode`.
La primera instalación mantiene modo seguro; un latch del watchdog en AppGroup
también obliga a deshabilitar tweaks hasta una habilitación explícita, nunca
se borra silenciosamente tras un panic. Los errores interrumpen la activación
antes de modificar PID 1 y dejan el estado disponible para recuperación.

Para posibles hijos RootHide lanzados directamente por PID 1 se añade un ajuste
**restringido** de `DYLD_IN_CACHE=0`: solo las rutas exactas `sshd`, `login` y
los tres gestores dentro de la raíz activa, después de verificar la procedencia
del hook y la presencia de `systemhook.dylib` en el entorno. Se conserva el resto
del entorno y quedan fuera hijos de otras raíces y aplicaciones no enumeradas.
En la revisión posterior a r175 se añade únicamente `xpcproxy` identificado
por las etiquetas exactas `UIKitApplication:` de Sileo, Zebra o RootHide:
son los casos que la evidencia física muestra lanzados indirectamente por
PID 1. No se cambia el entorno de otros trabajos xpcproxy, ni se suspenden
hijos o se invoca XPC síncrono desde launchd.

**Límites de esta integración:** `xpcproxy` puede arrancar Zebra/Sileo por un
camino distinto y NewTerm crea `login` desde su propia app, no necesariamente
desde PID 1. El plist OpenSSH ya se observó correctamente importado en r172,
pero no hay evidencia de que el proceso produzca un banner `SSH-2.0`.
Las pruebas host de esta revisión no comprueban dyld, trustcache ni la política
del kernel en el teléfono. El resultado de Xcode, el paquete íntegro y la
ejecución física se consignarán por separado; no instalar ni repetir pruebas
solo por haber pasado tests de host.

El botón **Cancelar solicitud pendiente de tweaks** está disponible en Ajustes
cuando RootHide está activo. Cancela únicamente el archivo de solicitud en
AppGroup sin cambiar el modo seguro real, el latch del watchdog ni reiniciar
servicios. Incluso si la app aún tiene `CS_INSTALLER`, un cambio desde Ajustes
**se guarda siempre como solicitud**, nunca elimina el marcador protegido:
la única aplicación del cambio ocurre antes de la nueva inyección de PID 1,
evitando competir con un panic del watchdog durante la sesión actual.

Si una solicitud pendiente contiene bytes o metadatos inválidos, la fase
instaladora únicamente puede forzar el modo seguro (sin inyectar tweaks), y
conserva el archivo para un reemplazo explícito posterior desde Ajustes. El
directorio secundario y su enlace deben seguir pasando la validación estricta;
los fallos de I/O o de identidad del bootstrap continúan abortando sin iniciar
la inyección de PID 1. Una nueva elección sustituye atómicamente solo el nombre
reservado para la solicitud; no sigue enlaces ni modifica otros archivos.

### Registros físicos r175 (23-10-2026) y corrección posterior

En los dos intentos registrados el flujo de explotación, boomerang, usuariospace
re-exec, registro de `jailbreakd`, reparación de enlaces de gestores y
preimportación de `com.openssh.sshd` pasa sus checkpoints. Tras solicitar
explícitamente tweaks y ejecutar otra activación, `safe_mode=0`, pero el proceso
`rh3tweakprobe` termina con `81`. El ejecutable define `81` como ausencia de la
marca del constructor `systemhook`; `82` significaría que ese constructor se
ejecutó pero no acreditó el `dlopen` de TweakLoader. La respuesta `0` al XPC
de parchear al hijo NO demuestra inserción de dylib.

La app de Dopamine pasa su entorno sin normalizar a `exec_cmd_roothide_spawn_traced`
en esa prueba. Esa ruta prepara trust/patch del hijo, pero no añade por sí misma
`DYLD_INSERT_LIBRARIES`: el verificador daba un falso negativo posible aun con
modo seguro desactivado. Ahora **únicamente para rh3tweakprobe** se construye
una copia efímera del entorno con `systemhook.dylib` del root activo verificado,
`DYLD_IN_CACHE=0` y sin variables de safe mode heredadas de la propia app.
También se eliminan las dos marcas de éxito heredadas para que nunca se pueda
fabricar un `exit 0` sin que el constructor las escriba realmente. No cambia
`environ` de Dopamine, ni los entornos de comandos generales, ni la política
de inyección de aplicaciones no relacionadas.

Los registros de Zebra muestran un PID válido tras `spawn`, pero el lanzamiento
físico más reciente pasa por `xpcproxy` y no por el binario directo. La
preparación de dyld de r175 no incluía ese caso, por lo que se extiende solo a
`UIKitApplication:` con el identificador exacto de los tres gestores incluidos.
Esto no prueba que Zebra llegue a `main` ni descarta fallos de dyld en una
biblioteca obligatoria. Tampoco se ha tocado su base de datos ni las fuentes APT.

El job OpenSSH está importado con programa y rutas esperados, sockets 22/2222,
pero se observó `state=not_running, runs=0` en `launchctl print`; esto **no
demuestra que se haya lanzado sshd** ni permite aislar un fallo de banner.
Conexión efectiva, salida/estado del hijo y contexto de dyld permanecen sin
evidencia. La alerta del RootHide Manager «SSH Server has been installed» solo
detecta el paquete, no un servidor atendiendo una conexión. El bootstrap donor
1900 ya trae `rootfs -> /` y `dev -> /dev`, por lo que no se reescriben esos
enlaces ni se desinstalan servicios por conjetura.

**Verificación**: las pruebas host del entorno del probe y del wrapper de PID1
ejercitan ramas reales en un arnés C, incluidos intentos de falsificar marcas,
etiquetas ajenas, flags de proceso y errores. Ni esas pruebas ni la compilación
Xcode acreditan comportamiento físico de SSH, tweaks, Zebra o aislamiento.

### Integración posterior a r176: montajes RootHide, reejecución Mach-O y launchd

El estado real de Actions #176 fue `failure`: su Xcode Build, validación de IPA
con jailbreak habilitado y publicación de release finalizaron con éxito, pero
la puerta estricta `Check RootHide port prerequisites before upload` falló por
las comprobaciones deliberadamente no satisfechas. No se interpreta el release
como validación física del bootstrap, SSH o los gestores.

Se encontró una diferencia funcional frente a RootHide 2 en el `jbctl internal
startup` heredado de Dopamine 3: volvía a invocar `protection_set_active(true)`
y montar `bindfs` sobre preboot/System y preboot/usr. El job startup se importa
desde el bootstrap oculto y está configurado con RunAtLoad. El RootHide Manager
mostró una alerta de montajes Bindfs desconocidos, pero no existen pruebas
físicas suficientes para identificar cada montaje de esa alerta. La nueva
política de `jbctl` impide tanto crear como desmontar estos montajes del sistema
en RootHide, e impide los comandos globales de fakelib en /usr/lib. **No intenta
desmontar montajes preexistentes**, que podrían pertenecer a otros componentes.
La ruta tradicional de Dopamine sigue disponible y se ejercita en pruebas host.

Importante: `jbctl` se lanza como proceso independiente, con `rootPath`
restaurado por su cliente pero `jbrand` local potencialmente cero. Por ello no
basta `roothide_is_active()` para el bloqueo de montajes. Se añade un criterio
de rechazo conservador para raíces con el formato exacto `.jbroot-` más 16
dígitos hexadecimales en Bundle/Application. Este criterio solo **niega** una
operación global: no asigna privilegios ni acepta un root nuevo. El arnés host
prueba RootHide con jbrand no disponible, RootHide completo, ruta malformada y
comportamiento stock, incluida ausencia de efectos de mount/unmount.

`ensure_randomized_cdhash_for_slice` podía abrir O_RDWR incluso si el Mach-O
ya contenía el jbrand actual; el propio código upstream advierte que esa
apertura puede producir EBADMACHO en iOS 16 si el binario sigue en ejecución.
Se incorpora una comprobación previa de CodeDirectory **solo lectura** para el
slice concreto. Si jbrand no está inicializado, el binario todavía no ha sido
adaptado o se requiere modificación, conserva la ruta de escritura existente.
Si un ejecutable ya marcado tiene firma inválida, falla sin reescribirlo.
Esto reduce escrituras innecesarias, pero **no demuestra la causa del EBADEXEC
físico de NewTerm**, ni modifica NewTerm o sus datos.

La ruta de arranque de PID 1 evita dereferenciar `path=NULL` al detectar el
primer xpcproxy o liberar el boot logo, y deja de registrar un PID de gestor
no confirmado si falla `posix_spawn`. La reparación SSH opt-in rechaza un
socket que declara expresamente UDP/no stream o `SocketPassive=false`, sin
alterar las opciones predeterminadas de los plists estándar. No se cambia la
activación real de sshd, su clave, la configuración OpenSSH, fuentes APT,
paquetes, datos de Zebra/Sileo ni los créditos.

La verificación en Windows es un gate de regresión, no una prueba del kernel.
Solo una ejecución física posterior puede certificar que `launchd` dispara el
job SSH, que `sshd` emite el banner SSH-2.0 y que tweaks, Sileo, Zebra y
NewTerm completan dyld y su inicialización. No se ha intentado desactivar la
seguridad de Revolut ni utilizar su alerta como una prueba de aislamiento.

### Corrección posterior a r177: validación de firmas Mach-O ya adaptadas

La ruta de lectura introducida en r177 para no reabrir ejecutables en O_RDWR
tenía dos casos de error verificables al inspeccionar el código. Podía entregar
un SuperBlob de `LC_CODE_SIGNATURE` a ChOma sin validar antes su rango, índices
y CodeDirectory; además, aceptaba un `jbrand` de la primera sección `__TEXT`
sin comprobar que el hash almacenado del slot de código 0 coincidiera con el
contenido actual. Si una escritura anterior se interrumpía tras cambiar la
marca, podía reutilizarse un CDHash con el primer slot obsoleto.

Ahora tanto la ruta de lectura como la de escritura validan los límites del
slice y reutilizan el mismo comprobador de SuperBlob de la recursión de
confianza. Cuando el fichero ya está marcado, la vía de solo lectura calcula
el hash de su primera página y exige coincidencia con el slot 0 antes de
devolver el CDHash. Ante firma malformada o hash discordante, falla cerrado:
**no intenta corregir en caliente ni reescribir el ejecutable afectado**.
El arnés host ejercita coincidencia, discrepancia, errores de lectura, hash no
calculable y parámetros inválidos; la validación estructural del SuperBlob
también se ejecuta con código C real y entradas negativas.

Esto refuerza seguridad y coherencia del proceso de confianza sin cambiar
PID 1, permisos CS, claves SSH, gestores o bootstrap instalado. Aún requiere
compilación macOS y prueba real en dispositivo para comprobar compatibilidad
con Mach-O/ChOma y determinar si afecta al `EBADEXEC` observado de NewTerm.
