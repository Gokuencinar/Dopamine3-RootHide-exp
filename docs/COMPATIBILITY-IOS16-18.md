# RootHide3 — objetivo multidispositivo iOS 16–18

Esta matriz es el **objetivo de ingeniería**, no una declaración de
compatibilidad física completada. Nunca convertir un resultado de compilación,
tests host, inspección de firmas o detección de exploit en una afirmación de
jailbreak funcional para todos los iPhone.

## Alcance técnico

| Familia | iOS 16 | iOS 17 | iOS 18 | Pruebas RootHide3 |
| --- | --- | --- | --- | --- |
| arm64 (A8–A11) | Perfil 1900, si versión y exploit admitidos | Solo combinaciones reales de dispositivo/iOS | Solo combinaciones reales de dispositivo/iOS | iPhone X iOS 16.7.15: evidencia **parcial**; falta validación integral |
| arm64e (A12–A13) | Perfil 1900; PPL | Perfil 1900; PPL o SPTM según plataforma | Perfil 1900; soporte Dopamine hasta 18.7.1 | Pendiente de hardware por firmware |
| arm64e (A14–A17) | Perfil 1900; PPL | Perfil 1900; Dopamine hasta 17.3.1, incluido caso SPTM | Fuera de matriz actual de exploits Dopamine | Pendiente de hardware por firmware |
| A18+ | No procede | No procede | Sin explotación general compatible | No anunciar soporte |

Consultar siempre la [matriz oficial de Dopamine](https://ellekit.space/dopamine/)
y las restricciones de firmware de cada iPhone. La presencia de `arm64e` en una
IPA no demuestra que exista un bypass de PPL/SPTM ni que el sistema permita
instalar el bootstrap oculto.

## Contratos que no se pueden romper

1. Conservar tanto los slices **arm64** como **arm64e** y los mecanismos
   existentes de Dopamine 3: kernel, PAC y PPL/SPTM, según combinación.
2. El preflight de RootHide comprueba primero la versión del perfil de
   bootstrap y después `DOEnvironmentManager.isSupported`; **no** fuerza
   un modelo, un chip ni una versión concreta. Un exploit ausente impide
   continuar antes de modificar el dispositivo.
3. El ABI 1900 de RootHide cubre iOS 16/17/18 como selección de paquetes;
   esto **no** certifica que la inicialización, rutas aleatorias,
   trustcache o servicios sean compatibles con cada kernel.
4. No usar offsets de dyld, hooks de vtable o layouts PAC de iOS 16 arm64
   como supuestos universales. iOS 18 y arm64e deben usar rutas validadas
   propias o conservar el comportamiento original si no hay soporte seguro.
5. Mantener las restricciones de confianza para el bootstrap activo,
   límites de privilegio, datos de usuario y fallos cerrados; no activar
   hooks globales experimentales para ampliar artificialmente la matriz.
6. Verificar en dispositivos reales, por separado: explotación y
   userspace reboot, RootHide oculto, carga de dyld/systemhook, Sileo,
   Zebra, RootHide Manager, OpenSSH/banner y ciclo de reinstalación.

## Evidencia conocida y pendiente

- iPhone X, iOS 16.7.15 (arm64): se alcanzó una activación parcial en
  candidatos anteriores; r183/r184 y estas rutas nuevas **no están
  validadas físicamente**.
- A12/A13, iOS 16, 17 y 18: falta un conjunto de pruebas físicas por
  versión de kernel/PPL/SPTM; los tests de host solo detectan regresiones.
- A14–A17, iOS 16 y hasta 17.3.1: requieren pruebas físicas por ABI
  arm64e y por variante de dyld. iOS 18 no puede habilitarse sin exploits.
- **Brecha dyld pendiente:** el código actual instala los hooks recursivos
  `dlopen` para `gDyld` en iOS 16/17 y para `gAPIs` solo en arm64. Si una
  versión arm64e expone únicamente `gAPIs`, falta esa cobertura; iOS 18 usa
  otras rutas y no instala estos cuatro hooks heredados. La implementación
  alternativa `devnoname120/roothide-dopamine3` valida stubs de dyld por
  firma, pero sus fixtures conocidos no certifican la ABI de iOS 18 ni
  justifican importar índices o parches sin verificación por firmware.
- **OTA dentro del mismo iOS mayor:** los perfiles actuales registran
  `OSMajor` y `ArchiveABI`, no el build exacto. No se debe interpretar una
  reactivación después de actualizar el firmware como validada sin un plan
  explícito de migración que preserve paquetes y datos existentes.
- Cualquier paquete de GitHub Actions se identifica como **experimental**.
  Un `Build` exitoso o una IPA firmada ad hoc no demuestra funcionalidad.
