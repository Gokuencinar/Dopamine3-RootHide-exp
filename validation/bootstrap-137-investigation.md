# Fallo del bootstrap en el iPhone X

Dispositivo: iPhone10,3, iOS 16.7.15 (20H380).
Fallo original: 19 de octubre de 2026, 06:34:28 UTC, beta aa6a60a.
Último diagnóstico: beta 9150bf2, 10:43:21 UTC.

El exploit, la comunicación con jailbreakd y la inyección en launchd llegaron
a funcionar. El script del bootstrap terminó con 137. Ese valor no distingue
si murió el shell o uno de sus hijos.

El diagnóstico posterior conserva `running-script`. La base de paquetes y
las bases de usuarios cambiaron durante el primer intento. No es seguro
tratar ese entorno como una extracción nueva.

Los seis postinst y prep_bootstrap.sh coinciden con el archivo original.
No apareció un informe de terminación relacionado en las dos carpetas
examinadas. Esto no demuestra que nunca se generara uno.

## Defecto encontrado en el port

El [systemhook original de RootHide](https://github.com/roothide/Dopamine2-roothide/blob/e8de6e5035fee52ca732536dbb3ca1734889d914/BaseBin/systemhook/src/roothider_main.c)
crea los hijos suspendidos, pide a jailbreakd que los prepare y los reanuda
cuando corresponde. También registra los cambios de proceso mediante SETEXEC.

El port conservaba ese control en el lanzador de la app, pero no en los
hooks de systemhook usados por sus descendientes. Añadir una firma a la
trustcache no sustituye esa preparación del proceso.

La corrección devuelve ese recorrido a los hijos de RootHide, conserva los
flags del llamador y cancela el seguimiento si falla SETEXEC. Si el daemon
rechaza un hijo recién creado, se termina y recoge ese hijo; no se deja
ejecutar sin preparar. DriverKit y Dopamine sin RootHide siguen su recorrido.
Los hijos inyectados conservan además DYLD_IN_CACHE=0.

Se usa el daemon existente y sus comprobaciones de parentesco y audit token.
No se añaden acciones privilegiadas al servidor de launchd.

## Qué falta comprobar

Este defecto es real, pero el log no demuestra que fuera quien produjo el
137 observado. La prueba nativa comprueba el orden de suspensión, preparación,
reanudación, restauración de flags y tratamiento de errores. No prueba los
parches de kernel o dyld en el iPhone.

El estado interrumpido sigue bloqueado. Recuperarlo requiere una operación
separada que conserve los datos y compruebe qué pasos quedaron aplicados.
Esta corrección no elimina marcadores, no renombra contenedores y no repite
prep_bootstrap.sh. No debe anunciarse como recuperación terminada.
