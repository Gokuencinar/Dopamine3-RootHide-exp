"""Execute production C with real crypto and compare with hashlib.

macOS uses CommonCrypto; Windows uses CryptoAPI adapters to the same digest
algorithms, in a separate executable (32-bit MinGW works with 64-bit Python).
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools.apply_choma_fixes import patched_source, ROOT


class PageHashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")
        if not compiler:
            raise unittest.SkipTest("C compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        prelude = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
typedef unsigned int CC_LONG;
typedef struct { HCRYPTPROV provider; HCRYPTHASH hash; } CC_SHA1_CTX;
typedef CC_SHA1_CTX CC_SHA256_CTX;
typedef CC_SHA1_CTX CC_SHA512_CTX;
static int hash_init(CC_SHA1_CTX *c, ALG_ID alg) {
    c->provider=0; c->hash=0;
    if (!CryptAcquireContextA(&c->provider,NULL,"Microsoft Enhanced RSA and AES Cryptographic Provider",24,CRYPT_VERIFYCONTEXT)) return 0;
    if (!CryptCreateHash(c->provider,alg,0,0,&c->hash)) { CryptReleaseContext(c->provider,0); return 0; }
    return 1;
}
static int hash_update(CC_SHA1_CTX *c, const void *data, CC_LONG n) { return CryptHashData(c->hash,(PBYTE)data,n,0); }
static int hash_final(uint8_t *out, CC_SHA1_CTX *c) {
    DWORD n=48; int ok=CryptGetHashParam(c->hash,HP_HASHVAL,out,&n,0);
    CryptDestroyHash(c->hash); CryptReleaseContext(c->provider,0); return ok;
}
#define CC_SHA1_Init(c) hash_init(c,0x8004)
#define CC_SHA256_Init(c) hash_init(c,0x800c)
#define CC_SHA384_Init(c) hash_init(c,0x800d)
#define CC_SHA1_Update hash_update
#define CC_SHA256_Update hash_update
#define CC_SHA384_Update hash_update
#define CC_SHA1_Final hash_final
#define CC_SHA256_Final hash_final
#define CC_SHA384_Final hash_final
#else
#include <openssl/sha.h>
typedef unsigned int CC_LONG;
typedef SHA_CTX CC_SHA1_CTX;
typedef SHA256_CTX CC_SHA256_CTX;
typedef SHA512_CTX CC_SHA512_CTX;
#define CC_SHA1_Init SHA1_Init
#define CC_SHA256_Init SHA256_Init
#define CC_SHA384_Init SHA384_Init
#define CC_SHA1_Update SHA1_Update
#define CC_SHA256_Update SHA256_Update
#define CC_SHA384_Update SHA384_Update
#define CC_SHA1_Final SHA1_Final
#define CC_SHA256_Final SHA256_Final
#define CC_SHA384_Final SHA384_Final
#endif
typedef struct { uint32_t codeLimit, nCodeSlots; uint8_t pageSize, hashType, hashSize; } CS_CodeDirectory;
typedef struct { const uint8_t *bytes; size_t length, maxRead, calls; int fail; } MachO;
#define MEMORY_STREAM_SIZE_INVALID ((size_t)-1)
#define CS_HASHTYPE_SHA160_160 1
#define CS_HASHTYPE_SHA256_256 2
#define CS_HASHTYPE_SHA256_160 3
#define CS_HASHTYPE_SHA384_384 4
static MachO *macho_get_stream(MachO *m) { return m; }
static size_t memory_stream_get_size(MachO *m) { return m->length; }
static int macho_read_at_offset(MachO *m, uint64_t off, size_t n, void *out) {
    m->calls++; if(n>m->maxRead)m->maxRead=n;
    if(m->fail || off>m->length || n>m->length-off) return -1;
    memcpy(out,m->bytes+off,n); return 0;
}
'''
        main = r'''
int main(int argc, char **argv) {
    if(argc!=9) return 2;
    FILE *f=fopen(argv[1],"rb"); if(!f)return 3;
    static uint8_t bytes[131072]; size_t size=fread(bytes,1,sizeof(bytes),f); fclose(f);
    CS_CodeDirectory cd={(uint32_t)strtoul(argv[2],NULL,10),(uint32_t)strtoul(argv[3],NULL,10),
        (uint8_t)atoi(argv[4]),(uint8_t)atoi(argv[5]),(uint8_t)atoi(argv[6])};
    MachO image={bytes,size,0,0,atoi(argv[8])}; uint8_t out[64]; memset(out,0xa5,sizeof(out));
    bool ok=code_directory_calculate_page_hash(&cd,&image,atoi(argv[7]),out);
    printf("%d %lu %lu ",ok,(unsigned long)image.maxRead,(unsigned long)image.calls);
    for(size_t i=0;i<sizeof(out);i++)printf("%02x",out[i]);
    puts(""); return 0;
}
'''
        source = prelude + (ROOT / "BaseBin/patches/choma_page_hash.c").read_text(encoding="utf-8") + main
        path = Path(cls.temp.name)
        (path / "test.c").write_text(source, encoding="utf-8")
        cls.executable = path / "page-hash.exe"
        cls.fixture = path / "input.bin"
        args = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",str(path/'test.c'),'-o',str(cls.executable)]
        if sys.platform == 'win32': args += ['-ladvapi32']
        elif sys.platform != 'darwin': args += ['-lcrypto']
        build=subprocess.run(args,capture_output=True,text=True)
        if build.returncode: raise RuntimeError(build.stderr)

    def calculate(self, data, directory, slot, fail=False):
        self.fixture.write_bytes(data)
        result=subprocess.run([str(self.executable),str(self.fixture),*map(str,directory),str(slot),str(int(fail))],check=True,capture_output=True,text=True)
        ok,max_read,calls,output=result.stdout.split()
        return bool(int(ok)),bytes.fromhex(output),int(max_read),int(calls)

    def test_known_digests_and_partial_final_pages(self):
        data = bytes(range(256))*33
        for page in (0,12,14):
            size = (1 << page) if page else len(data)
            count = (len(data)+size-1)//size
            for kind,hash_size,algorithm in ((1,20,'sha1'),(2,32,'sha256'),(3,20,'sha256'),(4,48,'sha384')):
                for slot in range(count):
                    with self.subTest(page=page,kind=kind,slot=slot):
                        ok,out,max_read,_=self.calculate(data,(len(data),count,page,kind,hash_size),slot)
                        self.assertTrue(ok)
                        self.assertEqual(out[:hash_size],hashlib.new(algorithm,data[slot*size:(slot+1)*size]).digest()[:hash_size])
                        self.assertEqual(out[hash_size:],bytes([0xA5])*(64-hash_size))
                        self.assertLessEqual(max_read,0x4000)
        ok,out,max_read,calls=self.calculate(data*3,(len(data)*3,1,0,4,48),0)
        self.assertTrue(ok)
        self.assertEqual(out[:48],hashlib.sha384(data*3).digest())
        self.assertEqual(max_read,0x4000)
        self.assertEqual(calls,2)

    def test_rejects_bad_geometry_before_io_and_keeps_output_untouched(self):
        cases = [((8192,2,p,2,32),0) for p in (1,16,20,31,32,255)]
        cases += [((0,1,12,2,32),0),((8193,3,12,2,32),0),
                  ((8192,1,12,2,32),0),((8192,2,12,2,48),0),
                  ((8192,2,12,99,32),0),((8192,2,12,2,32),-1),
                  ((8192,2,12,2,32),2)]
        for d,slot in cases:
            with self.subTest(directory=d,slot=slot):
                ok,out,_,calls=self.calculate(bytes(8192),d,slot)
                self.assertFalse(ok)
                self.assertEqual(calls,0)
                self.assertEqual(out,bytes([0xA5])*64)
        ok,out,_,_=self.calculate(bytes(8192),(8192,2,12,4,48),0,True)
        self.assertFalse(ok)
        self.assertEqual(out,bytes([0xA5])*64)

    def test_overlay_is_idempotent_and_rejects_drift(self):
        path=ROOT / 'BaseBin/ChOma/src/CodeDirectory.c'
        if not path.is_file(): self.skipTest('Pinned submodule not checked out')
        source=path.read_text(encoding='utf-8')
        fixed=patched_source(source)
        self.assertEqual(patched_source(fixed),fixed)
        with self.assertRaises(ValueError): patched_source(source.replace('return true;', 'return false;'))

    def test_randomization_preflights_before_disk_write(self):
        src=(ROOT/'BaseBin/libjailbreak/src/roothider/recdhash.m').read_text(encoding='utf-8')
        self.assertLess(src.index('unsupported code page layout:'),src.index('*rd2 = jbinfo(jbrand);'))
        self.assertNotIn('pageHash[codeDir.hashSize]',src)

    def test_build_applies_overlay_before_compiling_shared_choma(self):
        make=(ROOT/'BaseBin/Makefile').read_text(encoding='utf-8')
        section=make.split('ChOma: staging',1)[1].split('XPF:',1)[0]
        self.assertLess(section.index('tools/apply_choma_fixes.py'),section.index('$(MAKE) -C ChOma'))
        self.assertIn('CHOMA_PATH=../ChOma',make)
