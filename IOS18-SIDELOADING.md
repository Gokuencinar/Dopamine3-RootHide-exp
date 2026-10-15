# Objetivo: RootHide en iOS 18 mediante sideloading

Requisito del usuario, 15/10/2026: instalar la IPA con AltStore u otra plataforma
de sideloading, y usar el jailbreak con RootHide en los iPhone compatibles con
iOS 18. **La beta arm64e/iOS 15-16 no satisface ese requisito.**

## Alcance real de la base

Dopamine 3.0.11 declara soporte en iOS 18.0-18.7.1 para A12/A13: iPhone XS,
XS Max, XR, familia iPhone 11 y SE de segunda generación. En el código, la
combinación es ClearSword/DarkSword y momentarius. Titan no proporciona un
bypass para iOS 18 en A14 y posteriores; sus rangos terminan en 17.3.1.

Fuentes primarias: [Dopamine 3.0](https://github.com/opa334/Dopamine/releases/tag/3.0),
[página del desarrollador](https://ellekit.space/dopamine/), y los Info.plist de
los exploits de esta base, fijada en `448ff1a83d2bb807346f1f3d36332e4afbf9794a`.
El soporte de Dopamine no prueba el soporte del port RootHide.

## Bloqueos confirmados en este port

1. `DOJailbreaker.rootHidePreflightError` rechaza iOS 17 y posteriores antes de
   explotar. `prepareRootHideBootstrapWithCompletion:` también los rechaza antes
   de extraer archivos. Cambiar solo esos límites no adapta RootHide a iOS 18.
2. Solo se incluyen los bootstraps RootHide `1800` y `1900`. La selección,
   repositorios y paquetes están adaptados a iOS 15/16, sin evidencia de
   compatibilidad de instalación en iOS 18.
3. El código del donante en `roothider/unsandbox2.m` usa estructuras vnode y
   namecache y escrituras con `offsetof` de sus cabeceras. Despacha desde iOS
   16.4 sin distinguir iOS 18. Además, la ruta exige símbolos nchashtbl y
   nchashmask que no produce el XPF de esta base. No hay validación de estos
   parches para los kernels de iOS 18; no deben habilitarse por extrapolación.
4. Launchd, dyld, confianza, registro de aplicaciones y eliminación necesitan
   adaptación y pruebas en la combinación concreta de dispositivo/build. No
   existe en este repositorio evidencia de un arranque RootHide en iOS 18.

## Sideloading: corrección independiente ya implementada

La base de Dopamine conserva su vía de firma e instalación convencional; no se
debe equiparar sideloading a permisos privados concedidos por TrollStore. El
preflight inicial verifica recursos dentro del bundle, pero difiere la lectura
de otros contenedores cuando la app está en el sandbox. Tras elevar privilegios,
se vuelven a comprobar los conflictos y la propiedad antes de modificar archivos.

La firma final del dispositivo la realiza el instalador con su certificado y
perfil. No se ha producido ni probado aquí una firma Apple para un iPhone. La
presencia de entitlements en la IPA ad hoc no demuestra que iOS los conceda.
No se debe anunciar esta beta como instalada/probada mediante AltStore.

La [guía enlazada por el desarrollador](https://ios.cfw.guide/installing-dopamine/)
describe la instalación convencional de Dopamine. No es una certificación de
este port y no sustituye la inspección de una IPA realmente refirmada.

## Criterio para entregar una beta de iOS 18

Adaptar primero las rutas anteriores, verificar offsets/símbolos contra kernels
reales del rango elegido y el bootstrap/gestores para iOS 18. Después compilar,
inspeccionar la IPA refirmada y probar instalación, explotación, bootstrap,
arranque sin tweaks, gestores, reinicio y eliminación. Registrar modelo,
versión/build, commit y logs. Sin esos resultados, solo se puede declarar una
candidata no validada; no un jailbreak RootHide funcional para iOS 18.
