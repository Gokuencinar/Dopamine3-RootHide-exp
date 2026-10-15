# Revisión de firmas — 15 de octubre de 2026

Se corrigió el cálculo de hashes de páginas de ChOma: la ruta SHA-384 estaba usando SHA-256. También se sustituyó un buffer de tamaño variable por lectura en bloques de 16 KB.

La revisión comprueba tamaños, número de páginas y límites antes de generar los hashes. Cubre SHA-1, SHA-256, SHA-256 truncado y SHA-384, con tamaños de página 0, 12 y 14. El resultado solo se entrega si el cálculo termina bien.

El cambio se aplica con `tools/apply_choma_fixes.py` desde `BaseBin/patches/choma_page_hash.c`. Comprueba la huella de la fuente original, puede ejecutarse de nuevo y se detiene si la fuente ha cambiado. Se mantiene el submódulo fijado; XPF usa el mismo `CHOMA_PATH`.

Referencias: [ChOma usado como base](https://github.com/opa334/ChOma/tree/7dccded6bc17081c08f5f5cdbd7a4b051543a825) y [formato de firmas de Apple](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h).

Para revisar el parche:

```sh
python3 tools/apply_choma_fixes.py --check
python3 -m unittest discover -s tools/tests
```

La corrección está incluida en la compilación nativa `403be34`. Se revisaron los hashes de firma de la IPA y los binarios de `basebin.tar`. Falta comprobar su comportamiento en un iPhone.
