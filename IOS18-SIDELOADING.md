# Candidata experimental de RootHide para iOS 18

Esta revisión permite intentar el port en iOS 18 con la variante manual
Hardware Beta. No existe evidencia de instalación o arranque en un iPhone.
El build ordinario conserva el jailbreak deshabilitado.

## Alcance

La base Dopamine 3.0.11, commit `448ff1a83d2bb807346f1f3d36332e4afbf9794a`,
incluye ClearSword/DarkSword y momentarius para A12/A13 en iOS 18.0-18.7.1:
XS, XS Max, XR, familia 11 y SE de segunda generación. A14 y posteriores con
iOS 18 siguen sin una combinación de exploits disponible en esta base. No se
han alterado los rangos de exploits ni sustituido su comprobación por un
simple número de versión.

Fuentes: [Dopamine 3.0](https://github.com/opa334/Dopamine/releases/tag/3.0),
[desarrollador](https://ellekit.space/dopamine/).

## Cambios del port

- Perfil común a preflight e instalador: 1800 para iOS 15; 1900 para iOS 16 e
  iOS 18 experimental. Otros sistemas, incluidos 17 y 26, se rechazan. Se
  reutiliza el userspace arm64e fijado por SHA-256; no es un bootstrap nuevo
  certificado para iOS 18. Dopamine también utiliza 1900 como familia de
  userspace posterior, sin que eso pruebe los paquetes específicos de RootHide.
- El instalador vuelve a exigir `isSupported` antes de crear el contenedor.
  Se conservan aislamiento de /var/jb, comprobación de propietario,
  transacciones, fallo estricto de setup y arranque sin tweaks.
  Los contenedores nuevos registran el sistema mayor y ABI del archivo. Se
  rechaza reutilizar en iOS 18 un contenedor antiguo sin ese perfil, o uno
  cuyo perfil difiera, antes de re-randomizarlo o modificarlo.
- El hook `Loader::expandAtLoaderPath` y su trampolín se incluyen en el binario
  de dyld para iOS 18. La firma coincide con
  [Apple dyld-1285.19, Loader.cpp](https://github.com/apple-oss-distributions/dyld/blob/dyld-1285.19/dyld/Loader.cpp).
  MachOMerger debe resolverlo en el dyld real del dispositivo; si falta,
  retorna error. No se adivinan offsets de instrucciones ni se afirma que
  todos los builds conserven ese símbolo.
- La carga de dyld deja de exigir `loadDyldCache` fuera de iOS 15 arm64e:
  ese símbolo y su trampolín son exclusivos de la corrección del spinlock.
  Una imagen no cargable devuelve error en vez de abortar el daemon mediante
  un assert. También se comprueba el fallo de asignación de memoria.
- Se excluyen del enlace unsandbox.m, unsandbox1.m y unsandbox2.m. El informe
  anterior los describía como bloqueo de la ruta activa; las referencias
  demuestran que no se invocan. La elevación activa usa las primitivas de
  Dopamine 3, no esos layouts vnode/namecache del donante. Sus símbolos no se
  anuncian como adaptados a iOS 18.
- Para actualizar la información de dyld en task, se busca un único par
  dirección/tamaño en el task propio y se contrasta con task_info del objetivo.
  Se rechazan lecturas fallidas, ambigüedad, discrepancia y overflow. En iOS 18
  se escribe exclusivamente ese par y se comprueba el resultado. Se suprime
  el borrado heurístico de 48 bytes del donante, sin justificación en
  [XNU 11215 task.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/osfmk/kern/task.h)
  ni en [task_set_dyld_info de Apple](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.81.4/osfmk/kern/task.c).
  Es una adaptación experimental basada en fuente, pendiente de contraste
  con el kernel real; no garantiza atomicidad ni estabilidad.

## Evidencia y trabajo pendiente

Los tests de host comprueban selección del perfil, exclusiones de build,
enlace de hooks y guardas. En macOS un harness compila la función real de
actualización del task con memoria simulada: éxito, offsets ambiguos/ausentes,
discrepancia del objetivo, lectura y escritura fallidas. No usa un kernel real.

No están probados firmware/dpkg/gestores del bootstrap 1900 en iOS 18, firma
real de AltStore, merge del dyld del dispositivo, arranque de launchd,
registro de apps, ocultación, reinicio ni eliminación. Tests e IPA compilada
no resuelven esas incertidumbres. No distribuir como jailbreak funcional o
compatible con todos los iPhone de iOS 18.

El preflight permite sideloading convencional: comprueba recursos del bundle
y difiere las lecturas privilegiadas hasta después de la elevación. La firma
final depende del certificado y perfil del instalador. La
[guía enlazada por Dopamine](https://ios.cfw.guide/installing-dopamine/)
describe su instalación convencional, sin certificar este port.

Para pasar de candidata a soporte probado hace falta un iPhone A12/A13 con
build exacto, copia de datos y logs de instalación, primer arranque sin tweaks,
gestor, rejailbreak tras reinicio y eliminación. Cada fallo debe conservar su
estado de recuperación; no forzar la continuación modificando offsets,
hashes o marcadores.
