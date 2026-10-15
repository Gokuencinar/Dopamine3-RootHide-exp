# Pruebas en un iPhone

Todavía no hay resultados de hardware registrados para este port. Cuando se pruebe, hay que guardar los logs de cada caso en `validation/logs/`, quitar los datos personales y calcular su SHA-256.

El archivo `validation/device-tests.json` usa este formato:

```json
{
  "tested_commit": "40-character-Git-SHA",
  "device_model": "exact-iPhone-model",
  "ios_version": "exact-iOS-version",
  "scenarios": {
    "initial_boot": {
      "result": "pass",
      "log": "validation/logs/initial_boot.txt",
      "sha256": "64-character-sha256"
    }
  }
}
```

Es un ejemplo de estructura, no un resultado de prueba. Las ocho claves de escenarios están definidas en `tools/roothide_port_audit.py`: cubren arranque, bootstrap aislado, ocultación, gestores, inyección y blacklist, reinicios, eliminación y convivencia con Dopamine.

Cada resultado necesita su log real. El hash comprueba que el archivo no ha cambiado; no demuestra por sí mismo que la prueba sea correcta. No subas identificadores del dispositivo, contraseñas, tokens o datos de apps.

`tested_commit` debe ser un antecesor de la rama actual. Después solo se permiten cambios en `validation/`; cualquier cambio fuera de esa carpeta exige volver a validar. No se añaden resultados ficticios para hacer pasar la auditoría.
