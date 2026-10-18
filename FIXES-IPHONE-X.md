# Fallo al crear el bootstrap en iPhone X

El log de un iPhone10,3 con iOS 16.7.15 (20H380) llega a lectura/escritura del kernel y a la elevación de privilegios. Falla al crear `.jbroot` dentro de `/var/containers/Bundle/Application`, con `EPERM`.

En el port faltaba activar `CS_INSTALLER`, un paso que sí está en [la elevación de privilegios de RootHide 2](https://github.com/roothide/Dopamine2-roothide/blob/e8de6e5035fee52ca732536dbb3ca1734889d914/Application/Dopamine/Jailbreak/DOJailbreaker.m#L274). Se ha restaurado solo para RootHide usando las primitivas de Dopamine y se comprueba el resultado antes de preparar el bootstrap. El log nuevo muestra `RootHide installer access enabled` con UID y flags.

Es una corrección basada en esa diferencia de código. Falta repetir la prueba en el iPhone para confirmar que resuelve la denegación. No se cambian los permisos de la carpeta Application ni se borran contenedores para saltarse el error.

También se incorpora la corrección de Gokuencinar para `DuplicateIdentifier`: el Makefile pasa variables propias y solo el target Dopamine las usa para su identificador y nombre. El verificador revisa los identificadores del paquete real y rechaza duplicados entre la app, frameworks y extensiones.

La IPA original de la segunda beta tenía diez bundles con el mismo identificador. Instalar la versión reparada permite abrirla, pero no corrige el paso `CS_INSTALLER` del código nativo.
