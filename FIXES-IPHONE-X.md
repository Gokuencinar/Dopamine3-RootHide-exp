# Fallo al crear el bootstrap en iPhone X

El log de un iPhone10,3 con iOS 16.7.15 (20H380) llega a lectura/escritura del kernel y a la elevación de privilegios. Falla al crear `.jbroot` dentro de `/var/containers/Bundle/Application`, con `EPERM`.

En el port faltaba activar `CS_INSTALLER`, un paso que sí está en [la elevación de privilegios de RootHide 2](https://github.com/roothide/Dopamine2-roothide/blob/e8de6e5035fee52ca732536dbb3ca1734889d914/Application/Dopamine/Jailbreak/DOJailbreaker.m#L274). Se ha restaurado solo para RootHide usando las primitivas de Dopamine y se comprueba el resultado antes de preparar el bootstrap. El log nuevo muestra `RootHide installer access enabled` con UID y flags.

Es una corrección basada en esa diferencia de código. Falta repetir la prueba en el iPhone para confirmar que resuelve la denegación. No se cambian los permisos de la carpeta Application ni se borran contenedores para saltarse el error.

También se incorpora la corrección de Gokuencinar para `DuplicateIdentifier`: el Makefile pasa variables propias y solo el target Dopamine las usa para su identificador y nombre. El verificador revisa los identificadores del paquete real y rechaza duplicados entre la app, frameworks y extensiones.

La IPA original de la segunda beta tenía diez bundles con el mismo identificador. Instalar la versión reparada permite abrirla, pero no corrige el paso `CS_INSTALLER` del código nativo.

## Segundo fallo del tester: error 516 al mover `tmp` (18/10/2026)

Tras recuperar `CS_INSTALLER`, el iPhone X (iOS 16.7.15) ya creó
`.jbroot`, pero la extracción se detuvo moviendo `tmp` hacia
`AppGroup/.jbroot-.../var/tmp`, con `NSCocoaErrorDomain 516`
(`EEXIST`). Se verificó directamente en los dos archivos donor
`roothide_bootstrap_1800.tar.zst` y `roothide_bootstrap_1900.tar.zst`
de la IPA: ambos incluyen la carpeta real `./tmp/` y el enlace simbólico
`./var/tmp -> ../tmp`.

**Corrección candidata:** al mover `var/` a AppGroup, el enlace relativo
`var/tmp` pasa a estar roto. `fileExistsAtPath:` lo seguía y devolvía
`NO`, mientras que el siguiente `moveItemAtPath:` daba `EEXIST`.
Ahora se usa `lstat` y se exige que sea exactamente el enlace donor
`../tmp` antes de desvincularlo y mover la carpeta real `tmp`.
Si hay otra cosa en ese destino, se conserva y el instalador falla.

**Recuperación limitada:** para el iPhone X/iOS 16 y perfil 1900 se
reconoce solamente el par de carpetas `.jbroot` propiedad de root,
marcado como `creating`, con `var` y `private/var` enlazados como se
espera, sin enlace de retorno ni marcadores de instalación avanzada y con
el enlace donor `var/tmp`. Solo en ese caso se completa el movimiento
interrumpido y se crea el enlace de retorno, el perfil y la marca `layout`.
No se borran carpetas, archivos o estados de procedencia desconocida.

Estos cambios han pasado pruebas de contrato sobre el código, pero **no
confirman recuperación real en iPhone**. Si el directorio difiere de
este estado exacto, el port se detiene y requiere recuperación manual;
no repetir intentos ni borrar carpetas desconocidas.
