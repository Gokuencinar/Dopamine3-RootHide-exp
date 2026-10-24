#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/CodeDirectory.h>
#include <choma/MachOByteOrder.h>
#include <mach-o/dyld.h>
#include "signature_validation.h"
#include "../trustcache.h"
#include "../roothider.h"

#include <sys/stat.h>
#include <sys/mount.h>
#import <Foundation/Foundation.h>

#define DEBUG_LOG(...) //JBLogDebug(__VA_ARGS__)

MachO* fat_find_preferred_slice(Fat *fat)
{
	cpu_type_t cputype;
	cpu_subtype_t cpusubtype;
	if (host_get_cpu_information(&cputype, &cpusubtype) != 0) { return NULL; }

	MachO *candidateSlice = NULL;

	if (cpusubtype == CPU_SUBTYPE_ARM64E) {
		// New arm64e ABI
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2);
		if (!candidateSlice) {
			// Old arm64e ABI
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64E);
			if (candidateSlice) {
				// If we found an old arm64e slice, make sure this is a library! If it's a binary, skip!!!
				// For binaries the system will fall back to the arm64 slice, which has the CDHash that we want to add
				if (macho_get_filetype(candidateSlice) == MH_EXECUTE) candidateSlice = NULL;
			}
		}
	}

	if (!candidateSlice) {
		// On iOS 15+ the kernels prefers ARM64_V8 to ARM64_ALL
		candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_V8);
		if (!candidateSlice) {
			candidateSlice = fat_find_slice(fat, cputype, CPU_SUBTYPE_ARM64_ALL);
		}
	}

	return candidateSlice;
}

extern bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob);
extern bool rh3_code_directory_pages_match(MachO *macho, CS_DecodedBlob *best);

// ChOma's csd_superblob_decode() trusts the index table and each embedded
// blob's length. Check all of those untrusted offsets against the actual
// LC_CODE_SIGNATURE allocation before passing it to the decoder. A detached
// or CMS-signed SuperBlob still needs a usable CodeDirectory; the absence of
// one must never be confused with a valid non-ad-hoc signature.
bool rh3_signature_blob_is_well_formed(const CS_SuperBlob *superblob, uint32_t availableSize)
{
	if (!superblob || availableSize < sizeof(CS_SuperBlob)) return false;
	uint32_t magic = BIG_TO_HOST(superblob->magic);
	uint32_t length = BIG_TO_HOST(superblob->length);
	uint32_t count = BIG_TO_HOST(superblob->count);
	if ((magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_DETACHED_SIGNATURE) ||
	    length < sizeof(CS_SuperBlob) || length > availableSize ||
	    count > (length - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex)) return false;

	uint32_t indexEnd = sizeof(CS_SuperBlob) + count * sizeof(CS_BlobIndex);
	bool hasUsableCodeDirectory = false;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t type = BIG_TO_HOST(superblob->index[i].type);
		uint32_t offset = BIG_TO_HOST(superblob->index[i].offset);
		if (offset < indexEnd || offset > length || length - offset < sizeof(CS_GenericBlob))
			return false;

		const uint8_t *bytes = (const uint8_t *)superblob + offset;
		CS_GenericBlob header;
		memcpy(&header, bytes, sizeof(header));
		uint32_t blobMagic = BIG_TO_HOST(header.magic);
		uint32_t blobSize = BIG_TO_HOST(header.length);
		if (blobSize < sizeof(CS_GenericBlob) || blobSize > length - offset) return false;

		if (type == CSSLOT_CODEDIRECTORY ||
		    (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
			// Avoid ChOma hashing a truncated or non-CodeDirectory blob.
			if (blobMagic != CSMAGIC_CODEDIRECTORY ||
			    blobSize < offsetof(CS_CodeDirectory, spare2) + sizeof(uint32_t)) return false;
			const CS_CodeDirectory *cd = (const CS_CodeDirectory *)bytes;
			uint8_t hashType = cd->hashType;
			uint8_t hashSize = cd->hashSize;
			bool supportedHash = (hashType == CS_HASHTYPE_SHA160_160 && hashSize == 20) ||
			                     (hashType == CS_HASHTYPE_SHA256_160 && hashSize == 20) ||
			                     (hashType == CS_HASHTYPE_SHA256_256 && hashSize == 32) ||
			                     (hashType == CS_HASHTYPE_SHA384_384 && hashSize == 48);
			uint32_t hashOffset = BIG_TO_HOST(cd->hashOffset);
			uint32_t identOffset = BIG_TO_HOST(cd->identOffset);
			uint32_t codeSlots = BIG_TO_HOST(cd->nCodeSlots);
			uint32_t specialSlots = BIG_TO_HOST(cd->nSpecialSlots);
			// Only the page layouts supported by the patched ChOma consumer.
			// pageSize=0 is an unpaged signature; it is streamed in fixed chunks.
			uint32_t codeLimit = BIG_TO_HOST(cd->codeLimit);
			if (cd->pageSize != 0 && cd->pageSize != 12 && cd->pageSize != 14) return false;
			if (!codeLimit) return false;
			uint64_t pageBytes = cd->pageSize ? (UINT64_C(1) << cd->pageSize) : codeLimit;
			if (1 + ((uint64_t)codeLimit - 1) / pageBytes != codeSlots) return false;
			if (hashOffset > blobSize ||
			    identOffset < offsetof(CS_CodeDirectory, spare2) + sizeof(uint32_t) ||
			    identOffset >= hashOffset ||
			    !memchr(bytes + identOffset, '\0', hashOffset - identOffset) ||
			    (uint64_t)codeSlots * hashSize > blobSize - hashOffset ||
			    (uint64_t)specialSlots * hashSize > hashOffset) return false;
			if (supportedHash) hasUsableCodeDirectory = true;
		} else if (type == CSSLOT_SIGNATURESLOT && blobMagic != CSMAGIC_BLOBWRAPPER) {
			// Do not treat an arbitrary malformed CMS slot as a signed binary.
			return false;
		}
	}
	return hasUsableCodeDirectory;
}

NSString* resolveLoaderExecutablePaths(NSString *loadPath, NSString *loaderPath, NSString *mainExecutablePath)
{
	if ([loadPath hasPrefix:@"@loader_path/"] || [loadPath isEqualToString:@"@loader_path"]) {
		return [loadPath stringByReplacingCharactersInRange:NSMakeRange(0,sizeof("@loader_path")-1) withString:loaderPath.stringByDeletingLastPathComponent];
	}
	if ([loadPath hasPrefix:@"@executable_path/"] || [loadPath isEqualToString:@"@executable_path"]) {
		return [loadPath stringByReplacingCharactersInRange:NSMakeRange(0,sizeof("@executable_path")-1) withString:mainExecutablePath.stringByDeletingLastPathComponent];
	}
	return nil;
};

NSString* resolveRpaths(NSString *subPath, NSString *mainExecutablePath, NSArray* rpathStack)
{
@autoreleasepool {

	DEBUG_LOG("Resolving rpaths for %s, mainExecutable: %s, rpathStack: %s", subPath.fileSystemRepresentation, mainExecutablePath.fileSystemRepresentation, rpathStack.description.UTF8String);

	__block NSString *rpathResolvedPath = nil;

	for (NSString* loaderPath in rpathStack.reverseObjectEnumerator)
	{
		Fat *fat = fat_init_from_path(loaderPath.fileSystemRepresentation);
		if (fat) {
			MachO *macho = fat_find_preferred_slice(fat);
			if (macho) {
				macho_enumerate_rpaths(macho, ^(const char *rpathCStr, bool *stop) {
					NSString* possiblePath = [@(rpathCStr) stringByAppendingPathComponent:subPath];
					possiblePath = resolveLoaderExecutablePaths(possiblePath, loaderPath, mainExecutablePath) ?: possiblePath;
					if(![possiblePath hasPrefix:@"/"]) { // dyld only supports relative path in rpath on macOS
						JBLogDebug("Skipping relative rpath: %s -> %s", subPath.fileSystemRepresentation, possiblePath.fileSystemRepresentation);
						return;
					}
					if (_dyld_shared_cache_contains_path(possiblePath.fileSystemRepresentation)
					 || [[NSFileManager defaultManager] fileExistsAtPath:possiblePath]) {
						rpathResolvedPath = possiblePath;
						*stop = true;
					}
				});
			}
			fat_free(fat);
		}

		if(rpathResolvedPath)
			break;
	}

	return rpathResolvedPath;

} //autoreleasepool
}

NSString *resolveLoadPath(NSString *loadPath, NSString *loaderPath, NSString *mainExecutablePath, NSString* workingDir, NSArray* rpathStack)
{
	if (!loadPath) return nil;

	if ([loadPath hasPrefix:@"@rpath/"]) {
		return resolveRpaths([loadPath substringFromIndex:(sizeof("@rpath/")-1)], mainExecutablePath, rpathStack);
	}

	NSString *expandedPath = resolveLoaderExecutablePaths(loadPath, loaderPath, mainExecutablePath);
	if (expandedPath) {
		return expandedPath;
	}

	if([loadPath hasPrefix:@"@"]) { // dyld does not support this path
		JBLogDebug("Skipping unresolvable loadPath: %s", loadPath.fileSystemRepresentation);
		return nil;
	}

	if(![loadPath hasPrefix:@"/"])
	{
		JBLogDebug("Resolving relative path: %s", loadPath.fileSystemRepresentation);

		//non-@ path is treated as an implicit @rpath first
		NSString* resolvedPath = resolveRpaths(loadPath, mainExecutablePath, rpathStack);

		if(!resolvedPath && workingDir) {
			resolvedPath = [workingDir stringByAppendingPathComponent:loadPath];
		}

		return resolvedPath;
	}

	return loadPath; //absolute path
}

typedef struct {
	uint32_t Count;
	uint32_t* Types;
	uint32_t* Subtypes;
} preferredArchInfo;

#define RH3_MAX_TRUST_DEPENDENCIES 4096
#define RH3_MAX_TRUST_DEPTH 64

static void recurse_handler(NSString *loadPath, NSString *loaderPath, NSString *mainExecutablePath, NSString *workingDir, NSMutableArray* fileCaches, NSMutableArray* rpathStack, preferredArchInfo* preferredArch, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut, unsigned depth, bool required, bool *failed)
{
@autoreleasepool {
	if (*failed) return;
	if (depth > RH3_MAX_TRUST_DEPTH) {
		JBLogError("RootHide trust dependency recursion depth exceeded");
		*failed = true;
		return;
	}

	DEBUG_LOG("Recursing into loadPath: %s\n\tloader: %s\n\tmainExecutable: %s\nworkingDir: %s\n", loadPath.fileSystemRepresentation, loaderPath.fileSystemRepresentation, mainExecutablePath.fileSystemRepresentation, workingDir.fileSystemRepresentation);

	bool (^cdhashesContains)(cdhash_t) = ^bool(cdhash_t cdhash) {
		for (int i = 0; i < (*cdhashCountOut); i++) {
			if (!memcmp((*cdhashesOut)[i], cdhash, sizeof(cdhash_t))) {
				return true;
			}
		}
		return false;
	};
	void (^cdhashesAdd)(cdhash_t) = ^(cdhash_t cdhash) {
		if (*cdhashCountOut >= RH3_MAX_TRUST_DEPENDENCIES) {
			JBLogError("RootHide trust cdhash limit exceeded");
			*failed = true;
			return;
		}
		uint32_t newCount = *cdhashCountOut + 1;
		cdhash_t *resized = realloc(*cdhashesOut, (size_t)newCount * sizeof(cdhash_t));
		if (!resized) {
			JBLogError("Out of memory expanding RootHide trust cdhashes");
			*failed = true;
			return;
		}
		memcpy(resized[newCount - 1], cdhash, sizeof(cdhash_t));
		*cdhashesOut = resized;
		*cdhashCountOut = newCount;
	};


	NSString *resolvedLoadPath = resolveLoadPath(loadPath, loaderPath, mainExecutablePath, workingDir, rpathStack);
	if (!resolvedLoadPath) {
		JBLogError("Failed to resolve dependency library for %s (loader: %s, mainExecutable: %s)", loadPath.fileSystemRepresentation, loaderPath.fileSystemRepresentation, mainExecutablePath.fileSystemRepresentation);
		if (required) *failed = true;
		return;
	}

	if(_dyld_shared_cache_contains_path(resolvedLoadPath.fileSystemRepresentation)) {
		DEBUG_LOG("Skipping dyld shared cached library: %s", resolvedLoadPath.fileSystemRepresentation);
		return;
	}

	char realfilepath[PATH_MAX] = {0};
	int fd = open(resolvedLoadPath.fileSystemRepresentation, O_RDONLY);
	if (fd < 0) {
		JBLogError("Failed to open binary at path: %s (loader: %s)", resolvedLoadPath.fileSystemRepresentation, loaderPath.fileSystemRepresentation);
		if (required) *failed = true;
		return;
	}
	if (fcntl(fd, F_GETPATH, realfilepath) != 0) {
		JBLogError("Failed to get file path for fd %d", fd);
		close(fd);
		*failed = true;
		return;
	}
	close(fd);

	if(string_has_prefix(realfilepath, "/private/preboot/Cryptexes/")) {
		JBLogDebug("Skipping Cryptexes file: %s", realfilepath);
		return;
	}

	if(isRemovableBundlePath(realfilepath) && !hasTrollstoreLiteMarker(realfilepath)) {
		// ignore adhoc signed apps(removable system apps or other stuffs) which is not installed via tslite
		JBLogDebug("ignoring addhoc signed app: %s\n", realfilepath);
		return;
	}

	struct statfs fs;
	int sfsret = statfs(realfilepath, &fs);
	if(sfsret == 0) {
		if(strcmp(fs.f_mntonname, "/")==0 || strcmp(fs.f_mntonname, "/Developer")==0) {
			return;
		}
	}

	NSString* realLoadPath = @(realfilepath);

	DEBUG_LOG("loadPath = %s, \n\tresolvedLoadPath = %s, \n\trealLoadPath = %s\n", loadPath.fileSystemRepresentation, resolvedLoadPath.fileSystemRepresentation, realLoadPath.fileSystemRepresentation);

	if([fileCaches containsObject:realLoadPath]) {
		DEBUG_LOG("Skipping already parsed file: %s", realLoadPath.fileSystemRepresentation);
		return; // Already parsed
	}
	if (fileCaches.count >= RH3_MAX_TRUST_DEPENDENCIES) {
		JBLogError("RootHide trust dependency file limit exceeded");
		*failed = true;
		return;
	}
	//add realLoadPath to fileCaches
	[fileCaches addObject:realLoadPath];

	int backlinkError = ensure_jbroot_symlink(realLoadPath.fileSystemRepresentation);
	if (backlinkError != 0) {
		JBLogError("Unable to prepare RootHide @rpath backlink for %s: %d", realLoadPath.fileSystemRepresentation, backlinkError);
		// Match the existing weak/lazy dependency policy. A mandatory
		// library must not be silently declared trusted, but an optional
		// dependency may be skipped if its backlink cannot be prepared.
		if (required) *failed = true;
		return;
	}

	Fat *fat = fat_init_from_path(realLoadPath.fileSystemRepresentation);
	if (!fat) {
		JBLogError("Failed to parse fat binary at path: %s", realLoadPath.fileSystemRepresentation);
		*failed = true;
		return;
	}

	MachO *macho = NULL;
	if ([loadPath isEqualToString:mainExecutablePath]) {
		if (preferredArch->Count > 0) {
			for (size_t i = 0; i < preferredArch->Count; i++) {
				if (preferredArch->Types[i] != 0 && preferredArch->Subtypes[i] != UINT32_MAX) {
					macho = fat_find_slice(fat, preferredArch->Types[i], preferredArch->Subtypes[i]);
					if (macho) break;
				}
			}
		}
	}
	if (!macho) {
		macho = fat_find_preferred_slice(fat);
		if (!macho) {
			JBLogError("Failed to find preferred slice for file: %s", realLoadPath.fileSystemRepresentation);
			fat_free(fat);
			*failed = true;
			return;
		}
	}

		// A signed Mach-O must contain a readable SuperBlob and CodeDirectory.
		// ChOma does not bounds-check the SuperBlob index/child lengths itself.
		bool isAdhocSigned = false;
		uint32_t signatureOffset = 0, signatureSize = 0;
		if (macho_find_code_signature_bounds(macho, &signatureOffset, &signatureSize) != 0 ||
		    signatureSize < sizeof(CS_SuperBlob) ||
		    signatureOffset > macho->archDescriptor.size ||
		    signatureSize > macho->archDescriptor.size - signatureOffset) {
			JBLogError("Missing or invalid code signature bounds for %s", realLoadPath.fileSystemRepresentation);
			*failed = true;
		} else {
			CS_SuperBlob *superblob = macho_read_code_signature(macho);
			if (!superblob) {
				JBLogError("Missing or unreadable code signature for %s", realLoadPath.fileSystemRepresentation);
				*failed = true;
			} else {
				if (!rh3_signature_blob_is_well_formed(superblob, signatureSize)) {
					JBLogError("Malformed or missing CodeDirectory for %s", realLoadPath.fileSystemRepresentation);
					*failed = true;
				} else {
					CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
					if (!decodedSuperblob) {
						JBLogError("Failed to decode code signature for %s", realLoadPath.fileSystemRepresentation);
						*failed = true;
					} else {
						cdhash_t cdhash = {0};
						// Check the CodeDirectory for BOTH CMS and ad-hoc signatures.
						// A syntactically present CMS is not a cryptographic verification.
						if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhash, NULL) != 0) {
							JBLogError("Failed to calculate CDHash for %s", realLoadPath.fileSystemRepresentation);
							*failed = true;
						} else {
							isAdhocSigned = csd_superblob_is_adhoc_signed(decodedSuperblob);
								// An already-cached CDHash does not validate the installed
								// file: a modified later code page still fails in AMFI/dyld.
								// Reject it before either the cached fast path or a write.
								CS_DecodedBlob *best = csd_superblob_find_best_code_directory(decodedSuperblob);
								if (isAdhocSigned && !rh3_code_directory_pages_match(macho, best)) {
									JBLogError("Installed Mach-O code page signature mismatch: %s", realLoadPath.fileSystemRepresentation);
									*failed = true;
								}
								if (isAdhocSigned && !cdhashesContains(cdhash) &&
								    !*failed && !is_cdhash_trustcached(cdhash)) {
								int ret = ensure_randomized_cdhash_for_slice(realLoadPath.fileSystemRepresentation, macho->archDescriptor.offset, cdhash);
								if (ret == 0) {
									cdhashesAdd(cdhash);
								} else {
									JBLogError("ensure_randomized_cdhash_for_slice(%llx) failed: %s -> (%d)", macho->archDescriptor.offset, realLoadPath.fileSystemRepresentation, ret);
									*failed = true;
								}
							}
						}
						csd_superblob_free(decodedSuperblob);
					}
				}
				free(superblob);
			}
		}

		// If trust collection failed, never classify this Mach-O as exempt just
		// because it was not ad-hoc signed (or was already in the trust cache).
		if (*failed || !isAdhocSigned) {
			fat_free(fat);
			return;
		}
		// Always inspect dependencies for an ad-hoc Mach-O, even if its CDHash
		// was already queued or trusted: dependencies may have changed since.

	// Recurse this block on all dependencies
	macho_enumerate_dependencies(macho, ^(const char *pathCStr, uint32_t cmd, struct dylib* dylib, bool *stop) {
		if (*failed) {
			*stop = true;
			return;
		}

		NSMutableArray* nextChain = rpathStack.mutableCopy;
		[nextChain addObject:realLoadPath]; //Loading dependencies, add current macho itself to the rpath stack

			// A weak or lazy load may legitimately be absent. All other
			// dependencies must resolve or the collection is incomplete.
			bool dependencyRequired = cmd != LC_LOAD_WEAK_DYLIB && cmd != LC_LAZY_LOAD_DYLIB;
			recurse_handler(@(pathCStr), realLoadPath, mainExecutablePath, workingDir, fileCaches, nextChain, preferredArch, cdhashesOut, cdhashCountOut, depth + 1, dependencyRequired, failed);
		if (*failed) *stop = true;
	});

	fat_free(fat);

} //autoreleasepool
}

int recurse_collect_untrusted_cdhashes(const char *path, const char *callerImagePath, const char *callerExecutablePath, const char *workingDir, preferredArchInfo* preferredArch, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
	if (!path || !*path || !preferredArch || !cdhashesOut || !cdhashCountOut) return -1;
	bool failed = false;
	if(!callerExecutablePath) {
		callerExecutablePath = path;
	}

	NSMutableArray* rpathStack = [NSMutableArray array];

	[rpathStack addObject:@(callerExecutablePath)]; //initial rpath stack

	if(callerImagePath && strcmp(callerImagePath, callerExecutablePath) != 0) {
		[rpathStack addObject:@(callerImagePath)];
	}

	if(!callerImagePath) {
		callerImagePath = path;
	}

	NSMutableArray* fileCaches = [NSMutableArray array];

	recurse_handler(@(path), @(callerImagePath), @(callerExecutablePath), workingDir ? @(workingDir) : nil, fileCaches, rpathStack, preferredArch, cdhashesOut, cdhashCountOut, 0, true, &failed);

	DEBUG_LOG("fileCaches: %s", path, fileCaches.description.UTF8String);
	DEBUG_LOG("Finished collecting cdhashes for path: %s, found %u cdhashes, processed %d files", path, *cdhashCountOut, fileCaches.count);
	return failed ? -1 : 0;
}
