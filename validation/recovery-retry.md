# Recuperación del bootstrap interrumpido

En Ajustes, activa «Recuperar instalación interrumpida» después de reiniciar
completamente el iPhone. Pulsa Jailbreak. La opción se consume en ese intento.
Desactiva antes «Remove Jailbreak» si estaba activado.

Esta vía está limitada al caso de iOS 16 con una conservación anterior completa
y un bootstrap propio que quedó en `running-script`. Verifica el perfil,
propietario, identidades y reinicio posterior al fallo. Se detiene si encuentra
procesos usando las carpetas o no puede inspeccionarlos.

Conserva ambas carpetas actuales mediante renombrados exclusivos y un registro
nuevo `.roothide3-recovery-retry.plist`. No cambia el registro ni las copias de
la primera conservación, no borra marcadores y no repite scripts en el árbol
fallido. Si se interrumpe el movimiento, solo puede continuar esa transacción;
una identidad ambigua o un cambio de dispositivo a medias detiene el proceso.
Se permite una conservación adicional, no una cadena de reintentos automáticos.

Después crea otro bootstrap. Antes de configurar paquetes prueba shell, spawn
y SETEXEC. Ejecuta los comandos de la rama sin contraseña del donante fijado,
por separado y en el mismo orden. Cada paso guarda inicio, PID, resultado de
spawn, estado bruto de waitpid, salida y señal. Un fallo impide los pasos
siguientes. Una salida 137 no se confunde con una señal 9 del proceso observado;
un hijo interno todavía puede requerir su propio informe.

El script del donante debe conservar su hash esperado antes de comenzar. Solo
se retira del entorno nuevo después de completar todos los pasos. Las etapas
posteriores siguen comprobando las dependencias y los gestores antes de marcar
la instalación terminada.

Falta comprobar esta recuperación en el iPhone X con iOS 16.7.15. No demuestra
por sí sola que esté resuelto el error 137 ni la compatibilidad general del port.
