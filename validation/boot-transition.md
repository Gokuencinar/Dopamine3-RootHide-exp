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
