"""Run production trustcache upload/list code against a failure-injectable kernel mock.

No Apple headers or kernel access are needed.  The extracted functions are compiled
unchanged; only their external kernel primitives are replaced by the host fixture.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/libjailbreak/src/trustcache.c"


FIXTURE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef _WIN32
#include <malloc.h>
#else
#include <alloca.h>
#endif
#define usleep(duration) ((void)(duration))
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s\n",__LINE__,#expr); return 1; } } while (0)
typedef uint8_t uuid_t[16];
typedef uint8_t cdhash_t[20];
typedef struct trustcache_entry_v1 { uint8_t hash[20], hash_type, flags; } __attribute__((packed)) trustcache_entry_v1;
typedef struct { uint32_t version; uuid_t uuid; uint32_t length; trustcache_entry_v1 entries[]; } __attribute__((packed)) trustcache_file_v1;
typedef struct { uint64_t nextptr, prevptr, fileptr, size, type; } kernel_tc;
#define JB_MAGIC UINT64_C(0x424a424a424a424a)
#define JB_TRUSTCACHE_SIZE 0x4000
typedef struct { unsigned char trustcache[0x40]; uint64_t magic;
                 trustcache_file_v1 file; } __attribute__((packed)) jb_trustcache;
#define JB_TRUSTCACHE_ENTRY_COUNT ((JB_TRUSTCACHE_SIZE-sizeof(jb_trustcache))/sizeof(trustcache_entry_v1))
static int compare_entry(const void *a,const void *b) { return memcmp(a,b,20); }
static void _trustcache_file_sort(trustcache_file_v1 *file) {
    qsort(file->entries,file->length,sizeof(trustcache_entry_v1),compare_entry);
}
static void uuid_generate(uuid_t uuid) { memset(uuid,0x99,sizeof(uuid_t)); }
static void _trustcache_file_init(trustcache_file_v1 *file) {
    memset(file,0,sizeof(*file)); file->version=1; uuid_generate(file->uuid);
}
#define ksizeof(name) (sizeof(kernel_tc))
#define koffsetof(name, field) (offsetof(kernel_tc, field))
enum { pmap_image4_trust_caches=1, ppl_trust_cache_rt=2, txm_trustcache_root=3, SPTMArgs=4 };
static unsigned char memory[0x20000];
static uint64_t next_alloc = 0x6000;
static uint64_t root_addr = 0x1000;
static int sptm, fail_write_at, fail_read_at, fail_alloc, reads, writes, freed, bad_zero_write, published_before_retire;
static uint64_t old_cache;
static int within(uint64_t address, size_t length) { return address >= 0x1000 && address < sizeof(memory) && length <= sizeof(memory)-address; }
static uint64_t ksymbol(int symbol) { return symbol==pmap_image4_trust_caches && !sptm ? root_addr : symbol==SPTMArgs && sptm ? 1 : 0; }
static uint64_t ksymbol_txm(int symbol) { return sptm && symbol==txm_trustcache_root ? 0x1800 : 0; }
static int kreadbuf(uint64_t addr, void *dest, size_t size) {
    reads++;
    if (!within(addr, size) || (fail_read_at && reads == fail_read_at)) return -21;
    memcpy(dest, memory+addr, size); return 0;
}
static int kwritebuf(uint64_t addr, const void *src, size_t size) {
    if (!within(addr, size)) { bad_zero_write++; return -22; }
    writes++;
    if (fail_write_at && writes == fail_write_at) return -23;
    if (old_cache && addr==root_addr) {
        uint64_t next=0; memcpy(&next,src,sizeof(next));
        if (next!=old_cache && next!=0) published_before_retire++;
    }
    memcpy(memory+addr,src,size); return 0;
}
static int kwrite64(uint64_t addr,uint64_t value) { return kwritebuf(addr,&value,sizeof(value)); }
static int kalloc(uint64_t *addr,uint64_t size) {
    if (fail_alloc || size>0x4000 || next_alloc + 0x4000 >= sizeof(memory)) return -1;
    *addr=next_alloc; next_alloc+=0x4000; return 0;
}
static int kfree(uint64_t addr,uint64_t size) { (void)size; if (!within(addr,1)) return -1; freed++; return 0; }
static void setup(uint32_t count) {
    memset(memory,0,sizeof(memory)); next_alloc=0x6000; sptm=0;
    fail_write_at=fail_read_at=fail_alloc=reads=writes=freed=bad_zero_write=published_before_retire=0;
    old_cache=0x2000;
    kernel_tc hdr={0}; hdr.fileptr=old_cache+sizeof(kernel_tc);
    hdr.size=sizeof(kernel_tc)+sizeof(trustcache_file_v1)+count*sizeof(trustcache_entry_v1);
    hdr.type=5;
    memcpy(memory+old_cache,&hdr,sizeof(hdr));
    trustcache_file_v1 *file=(trustcache_file_v1 *)(memory+hdr.fileptr);
    file->version=1; file->length=count; memset(file->uuid,0x42,16);
    for (uint32_t i=0;i<count;i++) file->entries[i].hash[0]=0x11;
    memcpy(memory+root_addr,&old_cache,sizeof(old_cache));
    memcpy(memory+0x1800+0x20,&root_addr,sizeof(root_addr));
}
static trustcache_file_v1 *input(uint32_t count) {
    size_t size=sizeof(trustcache_file_v1)+count*sizeof(trustcache_entry_v1);
    trustcache_file_v1 *file=calloc(1,size);
    if (!file) exit(6);
    file->version=1; file->length=count; memset(file->uuid,0x42,16);
    for (uint32_t i=0;i<count;i++) file->entries[i].hash[0]=0x33;
    return file;
}
static uint64_t active_root(void) { uint64_t value=0; memcpy(&value,memory+root_addr,8); return value; }
static int old_unchanged(uint32_t count) {
    kernel_tc *hdr=(kernel_tc*)(memory+old_cache);
    trustcache_file_v1 *file=(trustcache_file_v1*)(memory+hdr->fileptr);
    return file->length==count && file->entries[0].hash[0]==0x11;
}
static int deny_host_malloc;
static void *checked_host_malloc(size_t size) { return deny_host_malloc ? NULL : malloc(size); }
/* PRODUCTION_LIST */
/* PRODUCTION_GROW */
/* PRODUCTION_ADD */
/* PRODUCTION_UPLOAD */
#define malloc checked_host_malloc
/* PRODUCTION_BUILD */
#undef malloc
int main(int argc,char **argv) {
    CHECK(argc==2);
    if (!strcmp(argv[1],"alloc-failure")) {
        setup(1); trustcache_file_v1 *file=input(2); fail_alloc=1;
        CHECK(trustcache_file_upload(file)!=0); CHECK(active_root()==old_cache);
        CHECK(old_unchanged(1) && freed==0); free(file);
    } else if (!strcmp(argv[1],"stage-write-failure")) {
        setup(1); trustcache_file_v1 *file=input(2); fail_write_at=1;
        CHECK(trustcache_file_upload(file)!=0); CHECK(active_root()==old_cache);
        CHECK(old_unchanged(1) && freed==1); free(file);
    } else if (!strcmp(argv[1],"stage-read-failure")) {
        setup(1); trustcache_file_v1 *file=input(2); fail_read_at=5;
        CHECK(trustcache_file_upload(file)!=0); CHECK(active_root()==old_cache);
        if (!(old_unchanged(1) && writes==1 && freed==1))
            fprintf(stderr,"read stage: reads=%d writes=%d freed=%d old_ok=%d\n",reads,writes,freed,old_unchanged(1));
        CHECK(old_unchanged(1) && writes==1 && freed==1); free(file);
    } else if (!strcmp(argv[1],"grow-replace")) {
        setup(1); trustcache_file_v1 *file=input(3);
        CHECK(trustcache_file_upload(file)==0); CHECK(active_root()!=old_cache);
        CHECK(old_unchanged(1) && freed==1 && published_before_retire>0);
        CHECK(((trustcache_file_v1*)(memory+((kernel_tc*)(memory+active_root()))->fileptr))->length==3);
        free(file);
    } else if (!strcmp(argv[1],"shrink-replace")) {
        setup(3); trustcache_file_v1 *file=input(1);
        CHECK(trustcache_file_upload(file)==0); CHECK(active_root()!=old_cache);
        CHECK(old_unchanged(3) && freed==1); free(file);
    } else if (!strcmp(argv[1],"same-size-replace")) {
        setup(1); trustcache_file_v1 *file=input(1);
        CHECK(trustcache_file_upload(file)==0 && active_root()!=old_cache);
        CHECK(old_unchanged(1) && freed==1); free(file);
    } else if (!strcmp(argv[1],"same-size-write-failure")) {
        setup(1); trustcache_file_v1 *file=input(1); fail_write_at=1;
        CHECK(trustcache_file_upload(file)!=0); CHECK(active_root()==old_cache);
        CHECK(old_unchanged(1)); free(file);
    } else if (!strcmp(argv[1],"insert-failure")) {
        setup(1); trustcache_file_v1 *file=input(3);
        /* Stage write succeeds; root pointer publication fails. */
        fail_write_at=2;
        CHECK(trustcache_file_upload(file)!=0); CHECK(active_root()==old_cache);
        /* Kernel write failure is ambiguous: keep the allocation, not a UAF. */
        CHECK(old_unchanged(1) && freed==0); free(file);
    } else if (!strcmp(argv[1],"remove-failure")) {
        setup(1); trustcache_file_v1 *file=input(2); fail_write_at=5;
        CHECK(trustcache_file_upload(file)!=0 && active_root()!=old_cache);
        CHECK(old_unchanged(1) && freed==0);
        CHECK(((kernel_tc*)(memory+active_root()))->nextptr==old_cache); free(file);
    } else if (!strcmp(argv[1],"fresh-insert")) {
        setup(1); memset(memory+root_addr,0,8); old_cache=0;
        trustcache_file_v1 *file=input(1);
        CHECK(trustcache_file_upload(file)==0 && active_root()!=0);
        CHECK(freed==0 && bad_zero_write==0); free(file);
    } else if (!strcmp(argv[1],"sptm-empty")) {
        setup(1); sptm=1; memset(memory+root_addr,0,8);
        CHECK(trustcache_list_insert(0x6000)!=0); CHECK(bad_zero_write==0);
    } else if (!strcmp(argv[1],"sptm-append")) {
        setup(1); sptm=1;
        CHECK(trustcache_list_insert(0x6000)==0);
        CHECK(((kernel_tc*)(memory+old_cache))->nextptr==0x6000);
        CHECK(((kernel_tc*)(memory+0x6000))->prevptr==old_cache);
        CHECK(active_root()==old_cache && bad_zero_write==0);
    } else if (!strcmp(argv[1],"grow-write-failure")) {
        setup(1); fail_write_at=1;
        CHECK(_jb_trustcache_grow()==0); CHECK(active_root()==old_cache);
        CHECK(old_unchanged(1) && freed==1);
    } else if (!strcmp(argv[1],"grow-insert-failure")) {
        setup(1); fail_write_at=3;
        CHECK(_jb_trustcache_grow()==0); CHECK(active_root()==old_cache);
        CHECK(old_unchanged(1) && freed==0);
    } else if (!strcmp(argv[1],"grow-success")) {
        setup(1);
        CHECK(_jb_trustcache_grow()==0x6000);
        CHECK(active_root()==0x6000 && freed==0);
        CHECK(((jb_trustcache *)(memory+0x6000))->magic==JB_MAGIC);
    } else if (!strcmp(argv[1],"grow-readback-failure")) {
        setup(1); fail_read_at=1;
        CHECK(_jb_trustcache_grow()==0); CHECK(active_root()==old_cache);
        CHECK(old_unchanged(1) && freed==1);
    } else if (!strcmp(argv[1],"jb-add-new")) {
        setup(1); trustcache_entry_v1 entry={0}; entry.hash[0]=0x66;
        CHECK(jb_trustcache_add_entries(&entry,1)==0 && active_root()==0x6000);
        jb_trustcache *cache=(jb_trustcache *)(memory+0x6000);
        CHECK(cache->file.length==1 && cache->file.entries[0].hash[0]==0x66);
    } else if (!strcmp(argv[1],"jb-add-write-failure")) {
        setup(1); trustcache_entry_v1 entry={0}; entry.hash[0]=0x66;
        CHECK(jb_trustcache_add_entries(&entry,1)==0);
        writes=0; fail_write_at=1; entry.hash[0]=0x77;
        CHECK(jb_trustcache_add_entries(&entry,1)!=0);
        jb_trustcache *cache=(jb_trustcache *)(memory+0x6000);
        CHECK(cache->file.length==1 && cache->file.entries[0].hash[0]==0x66);
    } else if (!strcmp(argv[1],"jb-add-read-failure")) {
        setup(1); trustcache_entry_v1 entry={0}; entry.hash[0]=0x66;
        CHECK(jb_trustcache_add_entries(&entry,1)==0);
        reads=0; writes=0; fail_read_at=1;
        CHECK(jb_trustcache_add_entries(&entry,1)!=0 && writes==0);
    } else if (!strcmp(argv[1],"jb-uuid-protected")) {
        setup(1);
        kernel_tc *header=(kernel_tc*)(memory+old_cache);
        memmove(memory+old_cache+offsetof(jb_trustcache,file),
                memory+header->fileptr,sizeof(trustcache_file_v1)+sizeof(trustcache_entry_v1));
        header->fileptr=old_cache+offsetof(jb_trustcache,file);
        uint64_t magic=JB_MAGIC;
        memcpy(memory+old_cache+offsetof(jb_trustcache,magic),&magic,sizeof(magic));
        trustcache_file_v1 *file=input(1);
        CHECK(trustcache_file_upload(file)!=0 && active_root()==old_cache);
        CHECK(writes==0 && freed==0); free(file);
    } else if (!strcmp(argv[1],"sptm-replace-denied")) {
        setup(1); sptm=1; trustcache_file_v1 *file=input(2);
        CHECK(trustcache_file_upload(file)!=0 && active_root()==old_cache);
        CHECK(writes==0 && freed==0); free(file);
    } else if (!strcmp(argv[1],"length-overflow")) {
        setup(1); trustcache_file_v1 *file=input(1); file->length=UINT32_MAX;
        CHECK(trustcache_file_upload(file)!=0 && active_root()==old_cache);
        CHECK(writes==0 && freed==0); free(file);
    } else if (!strcmp(argv[1],"build-valid")) {
        cdhash_t hash={0xAB}; trustcache_file_v1 *file=NULL;
        CHECK(trustcache_file_build_from_cdhashes(&hash,1,&file)==0);
        CHECK(file && file->length==1 && file->entries[0].hash[0]==0xAB);
        free(file);
    } else if (!strcmp(argv[1],"build-oom")) {
        cdhash_t hash={0xAB}; trustcache_file_v1 *file=NULL;
        deny_host_malloc=1;
        CHECK(trustcache_file_build_from_cdhashes(&hash,1,&file)!=0 && file==NULL);
    } else if (!strcmp(argv[1],"build-oversize")) {
        cdhash_t hash={0xAB}; trustcache_file_v1 *file=NULL;
        CHECK(trustcache_file_build_from_cdhashes(&hash,UINT32_MAX,&file)!=0 && file==NULL);
    } else if (!strcmp(argv[1],"null-input")) {
        CHECK(trustcache_file_upload(NULL)!=0);
    } else CHECK(0);
    return 0;
}
'''


class TrustcacheKernelIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            raise unittest.SkipTest("No host C compiler")
        source = SOURCE.read_text(encoding="utf-8")
        # These helpers must be in front of list_insert; extracted production
        # routines remain unmodified, including all write/read/rollback logic.
        list_start = source.index("static int tc_read64_checked(")
        list_end = source.index("int _trustcache_file_sort_entry_comparator_v1(", list_start)
        upload_start = source.index("int trustcache_file_upload(")
        upload_end = source.index("int trustcache_file_upload_with_uuid(", upload_start)
        grow_start = source.index("uint64_t _jb_trustcache_grow(")
        grow_end = source.index("int jb_trustcache_add_entries(", grow_start)
        add_start = grow_end
        add_end = source.index("int jb_trustcache_add_cdhashes(", add_start)
        build_start = source.index("int trustcache_file_build_from_cdhashes(")
        build_end = source.index("int trustcache_file_build_from_path(", build_start)
        fixture = FIXTURE.replace("/* PRODUCTION_LIST */", source[list_start:list_end]).replace(
            "/* PRODUCTION_UPLOAD */", source[upload_start:upload_end]
        ).replace("/* PRODUCTION_GROW */", source[grow_start:grow_end]).replace(
            "/* PRODUCTION_ADD */", source[add_start:add_end]
        ).replace("/* PRODUCTION_BUILD */", source[build_start:build_end]
        )
        cls.tempdir = tempfile.TemporaryDirectory(prefix="rh3-trustcache-io-")
        cls.addClassCleanup(cls.tempdir.cleanup)
        path = Path(cls.tempdir.name) / "trustcache_io.c"
        path.write_text(fixture, encoding="utf-8")
        cls.exe = Path(cls.tempdir.name) / "trustcache_io.exe"
        result = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(path),
                                 "-o", str(cls.exe)], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError("Production extraction failed to compile:\n" + result.stderr)

    def test_kernel_failure_paths_and_replacements(self):
        for case in ("alloc-failure", "stage-write-failure", "stage-read-failure",
                     "grow-replace", "shrink-replace", "same-size-replace",
                     "same-size-write-failure", "insert-failure", "remove-failure",
                     "fresh-insert", "sptm-empty", "sptm-append", "grow-write-failure",
                     "grow-insert-failure", "grow-success", "grow-readback-failure",
                     "jb-add-new", "jb-add-write-failure", "jb-add-read-failure",
                     "jb-uuid-protected", "sptm-replace-denied", "length-overflow",
                     "null-input", "build-valid", "build-oom", "build-oversize"):
            with self.subTest(case=case):
                result = subprocess.run([str(self.exe), case], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
