# Registro de apps y reinicio de userspace

El panic del iPhone X con iOS 16.7.15 muestra la muerte de PID 1 por SIGTRAP
tras completar el bootstrap. Todavía no identifica la comprobación que falló.

La candidata normaliza /var y /private/var. Si la caché apunta a un contenedor
RootHide anterior ausente, registra el bundle actual con uicache -p y vuelve a
comprobar la ruta. No elimina apps ni acepta duplicados que sigan existiendo.

El registro de arranque se autoriza mediante el dominio exclusivo de Dopamine.
Recibe el descriptor del log abierto antes de elevar privilegios, verifica su
ruta, propietario e identidad y conserva esos datos en el entorno de launchd.
Tras reexec abre el mismo archivo sin seguir enlaces ni crear destinos nuevos.
Cada marca se sincroniza para poder exportarla desde la app después de un panic.

Hay marcas para el logo, la recuperación de primitivos, los hooks y jailbreakd.
No se intercepta SIGTRAP ni se cambia la política de errores de PID 1. Estas
marcas permiten investigar el panic; no son una corrección demostrada del mismo.

Actualiza sin borrar la app. Mantén desactivadas recuperación y eliminación del
jailbreak. El bootstrap instalado se reutiliza y el script no vuelve a ejecutarse.

El intento 90d8f3d ya registra el diagnóstico y actualiza las apps. Sus últimas
marcas llegan a la llamada de reexec; no aparece la entrada del nuevo hook.
El panic repite los mismos frames que a566e9e.

Faltaba el paso que usa RootHide 2 para arrancar launchd suspendido y prepararlo
desde Boomerang antes de reanudarlo. El port restaura ambos lados juntos, solo
con RootHide activo. Boomerang espera hasta diez segundos a que PID 1 esté
suspendido; si la preparación falla, no lo reanuda. El log distingue espera,
preparación, reanudación y retorno inesperado de la llamada al kernel.

Esto corrige una omisión del código. Todavía no demuestra la causa exacta del
SIGTRAP ni que el reinicio vaya a completar en el iPhone.
