# RootHide3 — comparación funcional con devnoname120 (23/10/2026)

Fuente: `devnoname120/Dopamine`, rama `roothide-dopamine3`, SHA
`3a9c8dc212294f25fc9a03bba3aab38e1cc1a9a3`. La rama no tiene
validación física publicada en su README; su CI público de ese SHA falló.
Los testimonios de funcionamiento sin logs de firmware no equivalen a una
reproducción. El objetivo es adoptar **mecanismos comprobables** del código,
no trasplantar la rama completa ni alterar datos de un bootstrap instalado.

## Correcciones de esta fase

- `systemhook`: el inicializador `roothideinit.dylib` se carga tras el check-in
  también en procesos normales, como hace el fork. Anteriormente solo se
  cargaba si el ejecutable estaba dentro de `.jbroot`. Se mantienen límites
  de confianza al root activo y a la biblioteca root-owned; la redirección
  de HOME/pathhook sigue restringida a binarios de ese root.
- Bootstrap e inventario: los debs oficiales fijados traen `Sileo.app`
  uid 0 y `Zebra.app`/`RootHide.app` uid 501, incluso el directorio
  `Applications` de los últimos. El reparador de backlinks y el gate
  de registro obsoleto de LaunchServices reconocen únicamente esos bundles
  de uid 501, con verificaciones de modo, inode y O_NOFOLLOW. No hay `chown`
  recursivo ni aceptación de una aplicación arbitraria uid 501.
- Inicio de gestores: el fork ejecuta `uicache -p` al acabar la instalación;
  RootHide3 ahora registra exclusivamente bundles propios existentes antes
  de confirmar la primera finalización, con trust del binario, timeout
  separado para spawn y exit, y sin volver a registrar en cada reactivación.

## Bloqueos importantes **no resueltos**

- `launchdhook` del fork suspende y parchea hijos de PID 1 antes de dejarlos
  ejecutar; RootHide3 evita actualmente llamar al cliente XPC síncrono de
  jailbreakd desde PID 1. Copiarlo literalmente puede bloquear launchd.
  Queda pendiente un protocolo broker seguro, con tiempos acotados y pruebas
  del spawn de xpcproxy/sshd/gestores, antes de activarlo.
- El actual trustcache kernel contiene rutas de lectura/escritura cuyo error
  no se propaga en `jb_trustcache_add_entries` y `trustcache_file_upload`.
  Cualquier cambio de publicación de la lista enlazada requiere una prueba
  de reversión exacta; el código del fork tampoco certifica comportamiento
  de kernel en todos los iOS 16–18.
- La reparación de SSH sigue necesitando host key válida, servicio launchd
  rebasado al jbrand actual y una conexión TCP real para obtener el banner.
- `dyld` arm64e y iOS 18 aún requieren firmas/layout probados para ampliar
  los hooks `dlopen` sin arriesgar un bucle de arranque.

**Alcance de las pruebas:** host + compilación de CI si se obtiene; no
certifica OpenSSH, tweaks, esconder RootHide ni Sileo/Zebra en dispositivo.
