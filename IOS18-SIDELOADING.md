# iOS 18 y sideloading

En iOS 18, Dopamine admite A12/A13 hasta 18.7.1 y los dispositivos arm64 que puedan ejecutar ese sistema. A14 y posteriores quedan fuera porque esta base no tiene la combinación de exploits necesaria. La nueva candidata del port permite ambas arquitecturas.

La referencia es [Dopamine 3.0](https://github.com/opa334/Dopamine/releases/tag/3.0) y la [página de su desarrollador](https://ellekit.space/dopamine/). El port no amplía los rangos de esos exploits. La nueva candidata también contempla perfiles experimentales para iOS 17 y 26; el rango concreto sigue dependiendo de los exploits de Dopamine.

## Qué se ha adaptado

- Preflight e instalador comparten el perfil del bootstrap. iOS 16/17/18/26 usan el archivo 1900 de RootHide; su uso en los sistemas nuevos es experimental, sin dar por probados sus paquetes.
- Se comprueba la compatibilidad antes de crear el contenedor. En iOS 18 se rechaza reutilizar un contenedor sin perfil conocido o con otra versión mayor o ABI.
- Se incluye el hook `Loader::expandAtLoaderPath`. Su firma se contrastó con [el código de Apple](https://github.com/apple-oss-distributions/dyld/blob/dyld-1285.19/dyld/Loader.cpp); MachOMerger debe encontrarlo en el dyld del dispositivo o devolver error.
- `loadDyldCache` queda limitado a la corrección de iOS 15 arm64e. Los archivos `unsandbox*.m` del donante, que no forman parte de la ruta activa, se excluyen del enlace.
- La actualización de la información de dyld busca un par dirección/tamaño único y lo contrasta con `task_info`. Comprueba errores y límites antes de escribir. En iOS 18 se elimina el borrado heurístico de 48 bytes del donante; se tomó como referencia [task.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/osfmk/kern/task.h) y [task.c de Apple](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/osfmk/kern/task.c).

Estas comprobaciones tienen pruebas de host y de memoria simulada. Falta comprobarlas con el kernel y dyld reales de un iPhone.

## Instalar la IPA

La app permite iniciar el proceso con sideloading convencional: revisa los recursos del bundle y deja las lecturas privilegiadas para después de la elevación. La IPA necesita refirmarse con el certificado y perfil del instalador.

Todavía no se ha probado la instalación con AltStore, el arranque del bootstrap 1900 en iOS 18, los gestores, la inyección, la ocultación ni la recuperación. Los pasos están en [HARDWARE-BETA.md](HARDWARE-BETA.md).
