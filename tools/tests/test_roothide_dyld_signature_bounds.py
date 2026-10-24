"""Compile actual dyld signature helpers against tiny host Mach ABI shims.

RootHide's private dyld must not trust a malformed or truncated SuperBlob.
The test exercises native C extracted directly from lv_bypass.c without using
the connected phone or attempting an iOS signature bypass.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'BaseBin/dyldhook/src/lv_bypass.c'


class DyldSignatureBounds(unittest.TestCase):
    def test_real_c_helpers_reject_invalid_signature_and_offsets(self):
        cc = shutil.which('gcc') or shutil.which('clang') or shutil.which('cc')
        if not cc:
            self.skipTest('C compiler unavailable')
        source = SOURCE.read_text(encoding='utf-8')
        first = source[source.index('CS_SuperBlob *load_signature('):
                       source.index('unsigned code_directory_rank(')]
        second = source[source.index('bool superblob_is_adhoc_signed('):
                        source.index('// Resolved by main.S')]
        shims = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#define OSSwapBigToHostInt32(x) __builtin_bswap32((uint32_t)(x))
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0U
#define CSMAGIC_DETACHED_SIGNATURE 0xfade0cc1U
#define CSMAGIC_BLOBWRAPPER 0xfade0b01U
#define CSSLOT_SIGNATURESLOT 0x10000U
#define KERN_SUCCESS 0
#define VM_FLAGS_ANYWHERE 0
typedef uintptr_t vm_address_t;
typedef int kern_return_t;
typedef struct {uint32_t type, offset;} CS_BlobIndex;
typedef struct {uint32_t magic, length, count; CS_BlobIndex index[];} CS_SuperBlob;
typedef struct {uint32_t magic, length;} CS_GenericBlob;
typedef struct {uint8_t bytes[48];} CS_CodeDirectory;
typedef struct {
    off_t fs_file_start;
    void *fs_blob_start;
    size_t fs_blob_size;
} fsignatures_t;
static unsigned allocations;
static int mach_task_self(void) {return 1;}
static kern_return_t vm_allocate(int task, vm_address_t *addr, size_t size, int flags) {
    (void)task; (void)flags;
    allocations++;
    *addr=(uintptr_t)malloc(size);
    return *addr ? 0 : 1;
}
static kern_return_t vm_deallocate(int task, vm_address_t addr, size_t size) {
    (void)task; (void)size;
    free((void *)addr); return 0;
}
static void be32(void *dst, uint32_t value) {
    uint32_t encoded=__builtin_bswap32(value);
    memcpy(dst,&encoded,sizeof(encoded));
}
'''
        checks = r'''
int main(void) {
    unsigned char bytes[80]={0};
    CS_SuperBlob *blob=(CS_SuperBlob *)bytes;
    be32(&blob->magic,CSMAGIC_EMBEDDED_SIGNATURE);
    be32(&blob->length,12);
    be32(&blob->count,0);
    FILE *f=tmpfile();
    if (!f) return 100;
    if (fwrite(bytes,1,sizeof(bytes),f)!=sizeof(bytes) || fflush(f)) return 101;
    int fd=fileno(f);
    fsignatures_t fs={0};
    fs.fs_blob_size=12;
    CS_SuperBlob *loaded=load_signature(fd,&fs);
    if (!loaded) return 1;
    vm_deallocate(0,(vm_address_t)loaded,fs.fs_blob_size);
    if (!superblob_is_adhoc_signed(blob)) return 2;
    unsigned before=allocations;
    fs.fs_blob_size=4;
    if (load_signature(fd,&fs) || allocations!=before) return 3;
    fs.fs_blob_size=12;
    fs.fs_blob_start=(void *)(uintptr_t)4096;
    if (load_signature(fd,&fs) || allocations!=before) return 4;
    fs.fs_blob_start=0;
    fs.fs_file_start=(off_t)-2;
    if (load_signature(fd,&fs) || allocations!=before) return 5;
    fs.fs_file_start=0;
    fs.fs_blob_size=(size_t)-1;
    if (load_signature(fd,&fs) || allocations!=before) return 6;
    fs.fs_blob_size=12;
    be32(&blob->magic,0);
    if (superblob_is_adhoc_signed(blob)) return 7;
    fseek(f,0,SEEK_SET);
    fwrite(bytes,1,sizeof(bytes),f); fflush(f);
    if (load_signature(fd,&fs)) return 8;
    be32(&blob->magic,CSMAGIC_EMBEDDED_SIGNATURE);
    be32(&blob->count,1);
    be32(&blob->length,28);
    be32(&blob->index[0].type,CSSLOT_SIGNATURESLOT);
    be32(&blob->index[0].offset,50);
    if (superblob_is_adhoc_signed(blob)) return 9;
    be32(&blob->index[0].offset,20);
    CS_GenericBlob *wrapper=(CS_GenericBlob *)(bytes+20);
    be32(&wrapper->magic,CSMAGIC_BLOBWRAPPER);
    be32(&wrapper->length,8);
    if (!superblob_is_adhoc_signed(blob)) return 10;
    be32(&wrapper->length,0xffffffffU);
    if (superblob_is_adhoc_signed(blob)) return 11;
    be32(&wrapper->length,12);
    if (superblob_is_adhoc_signed(blob)) return 12;
    be32(&wrapper->length,8);
    be32(&wrapper->magic,0);
    if (superblob_is_adhoc_signed(blob)) return 13;
    be32(&wrapper->magic,CSMAGIC_BLOBWRAPPER);
    be32(&blob->index[0].offset,16);
    if (superblob_is_adhoc_signed(blob)) return 14;
    be32(&blob->index[0].offset,20);
    be32(&blob->length,8);
    if (superblob_is_adhoc_signed(blob)) return 15;
    be32(&blob->length,28);
    be32(&blob->count,0xffffffffU);
    if (superblob_is_adhoc_signed(blob)) return 16;
    fs.fs_blob_size=28;
    fseek(f,0,SEEK_SET);
    fwrite(bytes,1,sizeof(bytes),f); fflush(f);
    if (load_signature(fd,&fs)) return 17;
    fclose(f);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            cfile = Path(folder) / 'dyld_signature_bounds.c'
            executable = Path(folder) / 'dyld_signature_bounds.exe'
            cfile.write_text(shims + '\n' + first + '\n' + second + '\n' + checks,
                             encoding='utf-8')
            compile_ = subprocess.run([cc, '-std=c11', '-Wno-implicit-function-declaration',
                                       str(cfile), '-o', str(executable)],
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compile_.returncode, 0, compile_.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True,
                                    timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr +
                             f' (native failure #{result.returncode})')


if __name__ == '__main__':
    unittest.main()
