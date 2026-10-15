# Capturas de previsualización UIKit

Estas imágenes muestran una aplicación de previsualización aislada en un
simulador, con el aviso visible «VISTA PREVIA UIKIT · ESTADO SIMULADO».
No son capturas de la IPA de jailbreak instalada en un iPhone.

Se compilan los componentes visuales originales del repositorio: cabecera,
menús, celdas de créditos, fuentes y tema. Credits.plist se lee directamente,
incluida la sección RootHide 3 port / Gokuencinar. El controlador que compone
las pantallas es específico de la previsualización; no es DOMainViewController
ni el controlador Preferences del dispositivo. Los estados y acciones están
simulados. El botón Jailbreak no ejecuta nada. No se enlaza código de jailbreak.
El aspecto del sistema puede variar frente a iOS 18 por la versión del runtime.

La IPA del artefacto de créditos es una actualización de recursos sobre la
candidata nativa 403be34 previamente compilada e inspeccionada: se cambia
Credits.plist y se vuelve a firmar ad hoc el bundle. No constituye otra
compilación del código nativo. El hash mostrado por la app puede seguir siendo
403be34; credits-resource-revision.json registra ambas revisiones.

Las capturas y la refirma no prueban instalación mediante AltStore, explotación,
bootstrap, funcionamiento de tweaks ni estabilidad en un dispositivo físico.
