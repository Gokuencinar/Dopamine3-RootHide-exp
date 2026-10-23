#include "trustcache.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "kernel.h"
#include "info.h"
#include "primitives.h"

void _trustcache_file_init(trustcache_file_v1 *file)
{
	memset(file, 0, sizeof(*file));
	file->version = 1;
	uuid_generate(file->uuid);
}

// iOS 16:
// ppl_trust_cache_rt has trustcache runtime
// **(ppl_trust_cache_rt+0x20) seems to have the loaded trustcache linked list
// trustcache struct changed, "next" is still at +0x0, but "this" is at +0x20

uint64_t _trustcache_list_get_start(void)
{
	if (ksymbol(pmap_image4_trust_caches)) { // iOS <=15
		return kread64(ksymbol(pmap_image4_trust_caches));
	}
	else if (ksymbol(ppl_trust_cache_rt)) {  // iOS >=16, PPL
		return kread64(kread64(ksymbol(ppl_trust_cache_rt) + 0x20));
	}
	else if (ksymbol_txm(txm_trustcache_root)) { // iOS >=17, SPTM/TXM
		return kread64(kread64(ksymbol_txm(txm_trustcache_root) + 0x20));
	}

	return 0;
}

void _trustcache_list_set_start(uint64_t newStart)
{
	if (ksymbol(pmap_image4_trust_caches)) { // iOS <=15
		kwrite64(ksymbol(pmap_image4_trust_caches), newStart);
	}
	else if (ksymbol(ppl_trust_cache_rt)) {  // iOS >=16
		kwrite64(kread64(ksymbol(ppl_trust_cache_rt) + 0x20), newStart);
	}
	else if (ksymbol_txm(txm_trustcache_root)) { // iOS >=17, SPTM/TXM
		kwrite64(kread64(ksymbol_txm(txm_trustcache_root) + 0x20), newStart);
	}
}

void _trustcache_list_enumerate(void (^enumerateBlock)(uint64_t tcKaddr, bool *stop))
{
	uint64_t curTC = _trustcache_list_get_start();
	while(curTC != 0) {
		bool stop = false;
		enumerateBlock(curTC, &stop);
		if (stop) break;
		curTC = kread64(curTC + koffsetof(trustcache, nextptr));
	}
}

// kread64 returns zero on an I/O error, which is indistinguishable from a
// legitimate empty list. Mutating a linked list requires checked primitives.
static int tc_read64_checked(uint64_t address, uint64_t *value)
{
	if (!address || !value) return -1;
	return kreadbuf(address, value, sizeof(*value));
}

static int tc_write64_checked(uint64_t address, uint64_t value)
{
	if (!address) return -1;
	return kwrite64(address, value);
}

static int tc_root_location(uint64_t *location)
{
	if (!location) return -1;
	uint64_t pmapRoot = ksymbol(pmap_image4_trust_caches);
	if (pmapRoot) {
		*location = pmapRoot;
		return 0;
	}
	uint64_t runtime = ksymbol(ppl_trust_cache_rt);
	if (!runtime) runtime = ksymbol_txm(txm_trustcache_root);
	if (!runtime) return -1;
	if (tc_read64_checked(runtime + 0x20, location) != 0 || !*location) return -1;
	return 0;
}

static int tc_list_head_checked(uint64_t *head)
{
	uint64_t location = 0;
	if (tc_root_location(&location) != 0) return -1;
	return tc_read64_checked(location, head);
}

static int tc_set_list_head_checked(uint64_t newHead)
{
	uint64_t location = 0;
	if (tc_root_location(&location) != 0) return -1;
	return tc_write64_checked(location, newHead);
}

int trustcache_list_insert(uint64_t tcToInsert)
{
	if (!tcToInsert) return -1;

	if (ksymbol(SPTMArgs)) {
		// On SPTM/TXM devices, our allocations are read-only by TXM so it cannot write to the prevptr field 
		// Since TXM will only add trust caches to the start of the list, we simply add ours to the end
		// We avoid a panic when loading a new trustcache, since we guarantee the first trustcache in the list is always writable

		uint64_t lastTC = 0;
		if (tc_list_head_checked(&lastTC) != 0 || !lastTC) return -1;
		for (unsigned n = 0; n < 4096; n++) {
			uint64_t nextTC = 0;
			if (tc_read64_checked(lastTC + koffsetof(trustcache, nextptr), &nextTC) != 0)
				return -1;
			if (!nextTC) break;
			if (nextTC == lastTC || n == 4095) return -1;
			lastTC = nextTC;
		}
		if (koffsetof(trustcache, prevptr) &&
		    tc_write64_checked(tcToInsert + koffsetof(trustcache, prevptr), lastTC) != 0)
			return -1;
		return tc_write64_checked(lastTC + koffsetof(trustcache, nextptr), tcToInsert);
	}
	else {
		uint64_t previousStartTC = 0;
		if (tc_list_head_checked(&previousStartTC) != 0) return -1;
		if (tc_write64_checked(tcToInsert + koffsetof(trustcache, nextptr), previousStartTC) != 0)
			return -1;
		if (koffsetof(trustcache, prevptr) && previousStartTC &&
		    tc_write64_checked(previousStartTC + koffsetof(trustcache, prevptr), tcToInsert) != 0)
			return -1;
		if (tc_set_list_head_checked(tcToInsert) != 0) {
			if (koffsetof(trustcache, prevptr) && previousStartTC)
				(void)tc_write64_checked(previousStartTC + koffsetof(trustcache, prevptr), 0);
			return -1;
		}
		return 0;
	}
}

int trustcache_list_remove(uint64_t tcKaddr)
{
	if (!tcKaddr) return -1;
	uint64_t nextTc = 0, curTc = 0, prevTc = 0;
	const uint64_t prevOffset = koffsetof(trustcache, prevptr);
	if (tc_read64_checked(tcKaddr + koffsetof(trustcache, nextptr), &nextTc) != 0 ||
	    tc_list_head_checked(&curTc) != 0) return -1;
	for (unsigned n = 0; curTc && curTc != tcKaddr && n < 4096; n++) {
		prevTc = curTc;
		if (tc_read64_checked(curTc + koffsetof(trustcache, nextptr), &curTc) != 0 ||
		    curTc == prevTc) return -1;
	}
	if (curTc != tcKaddr) return -1;
	// Update the backlink first. A failed read-only/TXM write must not
	// unlink the existing cache and leave its neighbour inconsistent.
	if (nextTc) {
		if (prevOffset != 0) {
			if (tc_write64_checked(nextTc + prevOffset, prevTc) != 0)
				return -1;
		}
	}
	int status = prevTc ? tc_write64_checked(prevTc + koffsetof(trustcache, nextptr), nextTc) :
	                      tc_set_list_head_checked(nextTc);
	if (status != 0) {
		if (nextTc) {
			if (prevOffset != 0)
				(void)tc_write64_checked(nextTc + prevOffset, tcKaddr);
		}
		return -1;
	}
	return 0;
}

int _trustcache_file_sort_entry_comparator_v1(const void * vp1, const void * vp2)
{
	trustcache_entry_v1* tc1 = (trustcache_entry_v1*)vp1;
	trustcache_entry_v1* tc2 = (trustcache_entry_v1*)vp2;
	return memcmp(tc1->hash, tc2->hash, sizeof(cdhash_t));
}

void _trustcache_file_sort(trustcache_file_v1 *file)
{
	qsort(file->entries, file->length, sizeof(trustcache_entry_v1), _trustcache_file_sort_entry_comparator_v1);
}

bool _is_jb_trustcache(uint64_t tcKaddr)
{
	uint64_t jbTcFile = tcKaddr + offsetof(jb_trustcache, file);
	uint64_t file = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	if (file == jbTcFile) {
		// If there is exactly one 8-byte value between the kpage start and the trustcache file,
		// Check if that matches against the JB_MAGIC
		// This is a 100% accurate way of determining whether this entry is a jb_trustcache or not
		return (kread64(tcKaddr + offsetof(jb_trustcache, magic)) == JB_MAGIC);
	}
	return false;
}

void _jb_trustcache_enumerate(void (^enumerateBlock)(uint64_t jbTcKaddr, bool *stop))
{
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		if (_is_jb_trustcache(tcKaddr)) {
			enumerateBlock(tcKaddr, stop);
		}
	});
}

void jb_trustcache_clear(void)
{
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		kwrite64(jbTcKaddr + offsetof(jb_trustcache, file.length), 0);
	});
}

uint64_t _jb_trustcache_grow(void)
{
	uint64_t jbTcKern = 0;
	if (kalloc(&jbTcKern, 0x4000) != 0 || !jbTcKern) return 0;

	jb_trustcache *jbTc = alloca(sizeof(jb_trustcache));
	memset(jbTc, 0, sizeof(jb_trustcache));
	_trustcache_file_init(&jbTc->file);
	jbTc->magic = JB_MAGIC;
	*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, fileptr)) = (jbTcKern + offsetof(jb_trustcache, file));
	if (koffsetof(trustcache, size)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, size)) = JB_TRUSTCACHE_SIZE;
	}
	if (koffsetof(trustcache, type)) {
		*(uint64_t *)(jbTc->trustcache + koffsetof(trustcache, type)) = 0x5;
	}
	if (kwritebuf(jbTcKern, jbTc, sizeof(*jbTc)) != 0) {
		(void)kfree(jbTcKern, 0x4000);
		return 0;
	}
	jb_trustcache readback = {0};
	if (kreadbuf(jbTcKern, &readback, sizeof(readback)) != 0 ||
	    memcmp(&readback, jbTc, sizeof(readback)) != 0) {
		(void)kfree(jbTcKern, 0x4000);
		return 0;
	}
	if (trustcache_list_insert(jbTcKern) != 0) {
		// A failed kernel write may still have linked this allocation. Leaking
		// one page is safer than freeing memory reachable from the trustcache list.
		return 0;
	}
	return jbTcKern;
}

static int tc_find_free_jb_cache(uint64_t *freeKaddr, uint32_t *freeLength)
{
	if (!freeKaddr || !freeLength) return -1;
	*freeKaddr = 0;
	*freeLength = 0;
	uint64_t current = 0;
	if (tc_list_head_checked(&current) != 0) return -1;
	for (unsigned n = 0; current && n < 4096; n++) {
		uint64_t fileAddress = 0;
		if (tc_read64_checked(current + koffsetof(trustcache, fileptr), &fileAddress) != 0)
			return -1;
		if (fileAddress == current + offsetof(jb_trustcache, file)) {
			uint64_t magic = 0;
			if (tc_read64_checked(current + offsetof(jb_trustcache, magic), &magic) != 0)
				return -1;
			if (magic == JB_MAGIC) {
				uint32_t length = 0;
				if (kreadbuf(fileAddress + offsetof(trustcache_file_v1, length),
				             &length, sizeof(length)) != 0 || length > JB_TRUSTCACHE_ENTRY_COUNT)
					return -1;
				if (length < JB_TRUSTCACHE_ENTRY_COUNT) {
					*freeKaddr = current;
					*freeLength = length;
					return 0;
				}
			}
		}
		uint64_t next = 0;
		if (tc_read64_checked(current + koffsetof(trustcache, nextptr), &next) != 0 ||
		    next == current || (next && n == 4095)) return -1;
		current = next;
	}
	return 0;
}

int jb_trustcache_add_entries(struct trustcache_entry_v1 *entries, uint32_t entryCount)
{
	if (entryCount > 0 && !entries) return -1;
	uint32_t remainingEntryCount = entryCount;
	uint32_t insertedEntryCount = 0;
	while (remainingEntryCount > 0) {
		uint64_t freeJbTcKaddr = 0;
		uint32_t freeJbTcCurrentLength = 0;
		if (tc_find_free_jb_cache(&freeJbTcKaddr, &freeJbTcCurrentLength) != 0)
			return -1;
		if (freeJbTcKaddr == 0) {
			freeJbTcKaddr = _jb_trustcache_grow();
			if (freeJbTcKaddr == 0) return -1;
		}

		uint32_t entryCountToInsert = JB_TRUSTCACHE_ENTRY_COUNT - freeJbTcCurrentLength;
		if (remainingEntryCount < entryCountToInsert) {
			entryCountToInsert = remainingEntryCount;
		}

		jb_trustcache *jbTc = alloca(JB_TRUSTCACHE_SIZE);
		if (kreadbuf(freeJbTcKaddr, jbTc, JB_TRUSTCACHE_SIZE) != 0 ||
		    jbTc->file.length != freeJbTcCurrentLength) return -1;
		for (uint32_t i = 0; i < entryCountToInsert; i++) {
			// The input cursor must advance when this batch spans multiple
			// trustcache pages, otherwise each page repeats entries[0..N].
			jbTc->file.entries[freeJbTcCurrentLength+i] = entries[insertedEntryCount+i];
		}
		jbTc->file.length += entryCountToInsert;
		_trustcache_file_sort(&jbTc->file);
		if (kwritebuf(freeJbTcKaddr, jbTc, JB_TRUSTCACHE_SIZE) != 0) return -1;
		remainingEntryCount -= entryCountToInsert;
		insertedEntryCount += entryCountToInsert;
	}
	return 0;
}

int jb_trustcache_add_cdhashes(cdhash_t *hashes, uint32_t hashCount)
{
	if (hashCount == 0) return 0;
	if (!hashes || (size_t)hashCount > SIZE_MAX / sizeof(trustcache_entry_v1)) return -1;
	// A recursive trust request may contain thousands of binaries. A VLA
	// sized by its count can overflow jailbreakd/launchd's small stack.
	struct trustcache_entry_v1 *entries = calloc(hashCount, sizeof(*entries));
	if (!entries) return -1;
	for (uint32_t i = 0; i < hashCount; i++) {
		memcpy(entries[i].hash, hashes[i], sizeof(cdhash_t));
		entries[i].hash_type = 1;
		entries[i].flags = 0;
	}
	int result = jb_trustcache_add_entries(entries, hashCount);
	free(entries);
	return result;
}

int jb_trustcache_add_entry(struct trustcache_entry_v1 entry)
{
	return jb_trustcache_add_entries(&entry, 1);
}


/*int jb_trustcache_add_file(const char *filePath)
{
	
}

int jb_trustcache_add_directory(const char *directoryPath)
{

}*/

xpc_object_t jb_trustcache_info(void)
{
	xpc_object_t arr = xpc_array_create_empty();
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		xpc_object_t tcDict = xpc_dictionary_create_empty();
		xpc_dictionary_set_data(tcDict, "uuid", &uuid, sizeof(uuid));

		xpc_object_t hashesArr = xpc_array_create_empty();
		for (int i = 0; i < length; i++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[i]), &entry, sizeof(entry));
			xpc_array_set_data(hashesArr, XPC_ARRAY_APPEND, &entry.hash, sizeof(entry.hash));
		}
		xpc_dictionary_set_value(tcDict, "cdhashes", hashesArr);
		xpc_release(hashesArr);

		xpc_array_append_value(arr, tcDict);
		xpc_release(tcDict);
	});
	return arr;
}

void jb_trustcache_debug_print(FILE *f)
{
	__block int i = 0;
	_jb_trustcache_enumerate(^(uint64_t jbTcKaddr, bool *stop) {
		uuid_t uuid;
		kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.uuid), (void *)uuid, sizeof(uuid));
		uint32_t length = kread32(jbTcKaddr + offsetof(jb_trustcache, file.length));

		uint32_t *uuidData = (uint32_t *)uuid;
		fprintf(f, "Jailbreak TrustCache %d <%08x%08x%08x%08x> (length: %u) (kaddr: 0x%llx):\n", i++, htonl(uuidData[0]), htonl(uuidData[1]), htonl(uuidData[2]), htonl(uuidData[3]), length, jbTcKaddr);
		
		for (uint32_t j = 0; j < length; j++) {
			trustcache_entry_v1 entry;
			kreadbuf(jbTcKaddr + offsetof(jb_trustcache, file.entries[j]), &entry, sizeof(entry));
			fprintf(f, "| ");
			for (uint32_t k = 0; k < sizeof(cdhash_t); k++) {
				fprintf(f, "%02x", entry.hash[k]);
			}
			fprintf(f, "\n");
		}
	});
}

int trustcache_file_upload(trustcache_file_v1 *tc)
{
	// Always stage a new immutable cache. In-place writes can partially replace
	// the ONLY valid cache if the kernel primitive fails midway through a write.
	const size_t headerSize = ksizeof(trustcache);
	const size_t fileHeaderSize = sizeof(trustcache_file_v1);
	if (!tc || tc->version != 1 || headerSize >= 0x4000 ||
	    fileHeaderSize > 0x4000 - headerSize ||
	    tc->length > (0x4000 - headerSize - fileHeaderSize) / sizeof(trustcache_entry_v1) ||
	    koffsetof(trustcache, fileptr) > headerSize - sizeof(uint64_t) ||
	    (koffsetof(trustcache, size) && koffsetof(trustcache, size) > headerSize - sizeof(uint64_t)) ||
	    (koffsetof(trustcache, type) && koffsetof(trustcache, type) > headerSize - sizeof(uint64_t)))
		return -1;
	const size_t fileSize = fileHeaderSize + (size_t)tc->length * sizeof(trustcache_entry_v1);
	const size_t tcSize = headerSize + fileSize;

	uint64_t existingTcKaddr = 0;
	uint64_t oldTcSize = 0;
	uint64_t current = 0;
	if (tc_list_head_checked(&current) != 0) return -1;
	for (unsigned n = 0; current && n < 4096; n++) {
		uint64_t fileAddress = 0;
		uuid_t currentUUID = {0};
		if (tc_read64_checked(current + koffsetof(trustcache, fileptr), &fileAddress) != 0 ||
		    !fileAddress ||
		    kreadbuf(fileAddress + offsetof(trustcache_file_v1, uuid), currentUUID, sizeof(currentUUID)) != 0)
			return -1;
		if (memcmp(currentUUID, tc->uuid, sizeof(currentUUID)) == 0) {
			// Never replace the separately allocated dynamic JB trustcache.
			if (fileAddress == current + offsetof(jb_trustcache, file)) {
				uint64_t magic = 0;
				if (tc_read64_checked(current + offsetof(jb_trustcache, magic), &magic) != 0 ||
				    magic == JB_MAGIC) return -1;
			}
			uint32_t oldLength = 0;
			if (kreadbuf(fileAddress + offsetof(trustcache_file_v1, length),
			             &oldLength, sizeof(oldLength)) != 0 ||
			    oldLength > (0x4000 - headerSize - fileHeaderSize) / sizeof(trustcache_entry_v1))
				return -1;
			existingTcKaddr = current;
			oldTcSize = headerSize + fileHeaderSize + (size_t)oldLength * sizeof(trustcache_entry_v1);
			break;
		}
		uint64_t next = 0;
		if (tc_read64_checked(current + koffsetof(trustcache, nextptr), &next) != 0 ||
		    next == current || (next && n == 4095)) return -1;
		current = next;
	}
	// TXM's list root is read-only. Do not attempt to unlink an existing
	// cache using a write primitive that cannot make the transition atomic.
	if (existingTcKaddr && ksymbol(SPTMArgs)) return -1;

	uint8_t *prepared = calloc(1, tcSize);
	uint8_t *verified = malloc(tcSize);
	if (!prepared || !verified) {
		free(prepared);
		free(verified);
		return -1;
	}
	uint64_t tcKaddr = 0;
	if (kalloc(&tcKaddr, tcSize) != 0 || !tcKaddr) {
		free(prepared);
		free(verified);
		return -1;
	}
	const uint64_t fileAddress = tcKaddr + headerSize;
	memcpy(prepared + koffsetof(trustcache, fileptr), &fileAddress, sizeof(fileAddress));
	if (koffsetof(trustcache, size)) {
		uint64_t sizeField = tcSize;
		memcpy(prepared + koffsetof(trustcache, size), &sizeField, sizeof(sizeField));
	}
	if (koffsetof(trustcache, type)) {
		uint64_t type = 0x5;
		memcpy(prepared + koffsetof(trustcache, type), &type, sizeof(type));
	}
	memcpy(prepared + headerSize, tc, fileSize);
	int result = kwritebuf(tcKaddr, prepared, tcSize);
	if (result == 0) result = kreadbuf(tcKaddr, verified, tcSize);
	if (result == 0 && memcmp(prepared, verified, tcSize) != 0) result = -1;
	free(prepared);
	free(verified);
	if (result != 0) {
		(void)kfree(tcKaddr, tcSize);
		return -1;
	}

	// First publish the complete replacement; only then unlink the old UUID.
	// This makes allocation and I/O failures leave the old cache untouched.
	if (trustcache_list_insert(tcKaddr) != 0) {
		// A failed primitive could have published a pointer despite returning
		// error. Avoid freeing a possibly linked allocation (kernel UAF).
		return -1;
	}
	if (existingTcKaddr) {
		if (trustcache_list_remove(existingTcKaddr) != 0) {
			// Both caches remain valid when unlinking is denied; never free one
			// that the kernel may still traverse.
			return -1;
		}
		usleep(10000); // best-effort grace period; NOT a lock against readers
		if (kfree(existingTcKaddr, oldTcSize) != 0) return -1;
	}
	return 0;
}

int trustcache_file_upload_with_uuid(trustcache_file_v1 *tc, uuid_t uuid)
{
	if (!tc || !uuid) return -1;
	memcpy(tc->uuid, uuid, sizeof(uuid_t));
	return trustcache_file_upload(tc);
}

int trustcache_file_build_from_cdhashes(cdhash_t *CDHashes, uint32_t CDHashCount, trustcache_file_v1 **tcOut)
{
	if (!tcOut) return -1;
	*tcOut = NULL;
	// The uploader accepts a single 16 KiB cache, not an unbounded array.
	// Reject overlarge counts before allocating or indexing caller hashes.
	if (!CDHashes || CDHashCount == 0 ||
	    sizeof(trustcache_file_v1) >= 0x4000 ||
	    CDHashCount > (0x4000 - sizeof(trustcache_file_v1)) / sizeof(trustcache_entry_v1))
		return -1;

	size_t tcSize = sizeof(trustcache_file_v1) + (sizeof(trustcache_entry_v1) * CDHashCount);
	trustcache_file_v1 *file = malloc(tcSize);
	if (!file) return -1;
	_trustcache_file_init(file);

	file->length = CDHashCount;
	for (uint32_t i = 0; i < CDHashCount; i++) {
		memcpy(file->entries[i].hash, CDHashes[i], sizeof(cdhash_t));
		file->entries[i].hash_type = 2;
		file->entries[i].flags = 0;
	}
	_trustcache_file_sort(file);

	*tcOut = file;
	return 0;
}

int trustcache_file_build_from_path(const char *filePath, trustcache_file_v1 **tcOut)
{
	if (!filePath || !tcOut) return -1;
	*tcOut = NULL;
	int fd = open(filePath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) return -1;
	struct stat s = { 0 };
	if (fstat(fd, &s) != 0 || !S_ISREG(s.st_mode) ||
	    s.st_size < (off_t)sizeof(trustcache_file_v1) ||
	    s.st_size > 0x4000) {
		close(fd);
		return -1;
	}

	size_t tcSize = (size_t)s.st_size;
	trustcache_file_v1 *file = malloc(tcSize);
	if (!file) {
		close(fd);
		return -1;
	}
	size_t copied = 0;
	while (copied < tcSize) {
		ssize_t count = read(fd, (uint8_t *)file + copied, tcSize - copied);
		if (count < 0 && errno == EINTR) continue;
		if (count <= 0) {
			free(file);
			close(fd);
			return -1;
		}
		copied += (size_t)count;
	}
	close(fd);

	// Validate the serialized length without multiplication overflow or
	// accepting short reads. Never upload uninitialized trustcache entries.
	size_t dataSize = tcSize - sizeof(trustcache_file_v1);
	if (file->version != 1 || file->length == 0 ||
	    dataSize % sizeof(trustcache_entry_v1) != 0 ||
	    (size_t)file->length != dataSize / sizeof(trustcache_entry_v1)) {
		free(file);
		return -1;
	}

	*tcOut = file;
	return 0;
}

bool trustcache_contains_cdhash(uint64_t tcKaddr, cdhash_t CDHash)
{
	uint64_t tcFileKaddr = kread64(tcKaddr + koffsetof(trustcache, fileptr));
	uint32_t length = kread32(tcFileKaddr + offsetof(trustcache_file_v1, length));
	if (length == 0) return false;

	int32_t left = 0;
	int32_t right = length - 1;

	while (left <= right) {
		int32_t mid = (left + right) / 2;
		cdhash_t itCDHash;
		kreadbuf(tcFileKaddr + offsetof(trustcache_file_v1, entries[mid].hash), itCDHash, CS_CDHASH_LEN);
		int32_t cmp = memcmp(CDHash, itCDHash, CS_CDHASH_LEN);
		if (cmp == 0) {
			return true;
		}
		if (cmp < 0) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
	}
	return false;
}

bool is_cdhash_trustcached(cdhash_t CDHash)
{
	__block bool inTrustCache = false;
	_trustcache_list_enumerate(^(uint64_t tcKaddr, bool *stop) {
		bool inThisTrustCache = trustcache_contains_cdhash(tcKaddr, CDHash);
		if (inThisTrustCache) {
			inTrustCache = true;
			*stop = true;
		}
	});
	return inTrustCache;
}
