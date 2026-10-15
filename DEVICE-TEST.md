# App de diagnóstico

`RootHide3-Device-Test.ipa` sirve para probar la instalación y apertura de una app sencilla. No lleva código de jailbreak, bootstrap ni instaladores de paquetes.

Su identificador es `com.gokuencinar.roothide3.diagnostic`. Necesita refirmarse para instalarla en un iPhone. Que esta app abra correctamente no demuestra que la beta de jailbreak funcione.

Para generarla en macOS:

```sh
gmake -C Application diagnostic
python3 tools/verify_roothide_device_test.py --ipa Application/RootHide3-Device-Test.ipa --json
```

La variante que permite intentar el jailbreak está explicada en [HARDWARE-BETA.md](HARDWARE-BETA.md).
