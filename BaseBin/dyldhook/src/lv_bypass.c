#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sandbox.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <libkern/OSByteOrder.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"
#include "dyld.h"

#include <libjailbreak/jbclient_mach.h>
#include <libjailbreak/codesign.h>

// Library validation bypass
// Dyld will call fcntl to attach a code signature to a dylib before mapping it in
// So we hook fcntl to ensure the code signature to be attached is added to trustcache

bool proc_has_bootstrap_port(void)
{
	static bool hasBootstrapPort = false;
	static bool didCheckBootstrapPort = false;

	if (!didCheckBootstrapPort) {
		mach_port_t launchdPort = MACH_PORT_NULL;
		task_get_bootstrap_port(task_self_trap(), &launchdPort);
		if (launchdPort) {
			mach_port_deallocate(task_self_trap(), launchdPort);
		}
		hasBootstrapPort = launchdPort != MACH_PORT_NULL;
		didCheckBootstrapPort = true;
	}

	return hasBootstrapPort;
}

CS_SuperBlob *load_signature(int fd, const fsignatures_t *fs)
{
	// File offsets come from a package's signature command. Reject unbounded
	// or truncated reads before allocating memory in the private dyld process.
	if (!fs || fs->fs_file_start < 0 ||
	    fs->fs_blob_size < sizeof(CS_SuperBlob) ||
	    fs->fs_blob_size > (16U * 1024U * 1024U)) return NULL;
	uint64_t fileStart = (uint64_t)fs->fs_file_start;
	uint64_t blobStart = (uintptr_t)fs->fs_blob_start;
	uint64_t superblobSize = fs->fs_blob_size;
	if (fileStart > INT64_MAX || blobStart > INT64_MAX - fileStart) return NULL;
	uint64_t superblobStart = fileStart + blobStart;
	off_t oldPos = lseek(fd, 0, SEEK_CUR);
	if (oldPos < 0) return NULL;
	off_t endPos = lseek(fd, 0, SEEK_END);
	if (lseek(fd, oldPos, SEEK_SET) != oldPos || endPos < 0 ||
	    superblobStart > (uint64_t)endPos ||
	    superblobSize > (uint64_t)endPos - superblobStart) return NULL;

	vm_address_t addr;
	kern_return_t kr = vm_allocate(mach_task_self(), &addr, superblobSize, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) return NULL;

	if (lseek(fd, (off_t)superblobStart, SEEK_SET) != (off_t)superblobStart ||
	    read(fd, (void *)addr, (size_t)superblobSize) != (ssize_t)superblobSize) {
		vm_deallocate(mach_task_self(), addr, superblobSize);
		return NULL;
	}
	CS_SuperBlob *superblob = (CS_SuperBlob *)addr;
	uint32_t magic = OSSwapBigToHostInt32(superblob->magic);
	uint32_t declaredLen = OSSwapBigToHostInt32(superblob->length);
	uint32_t count = OSSwapBigToHostInt32(superblob->count);
	if ((magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_DETACHED_SIGNATURE) ||
	    declaredLen < sizeof(CS_SuperBlob) || declaredLen > superblobSize ||
	    count > (declaredLen - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex)) {
		vm_deallocate(mach_task_self(), addr, superblobSize);
		return NULL;
	}

	return superblob;
}

unsigned code_directory_rank(const CS_CodeDirectory *cd)
{
	// The supported hash types, ranked from least to most preferred. From XNU's
	// bsd/kern/ubc_subr.c.
	static uint32_t rankedHashTypes[] = {
		CS_HASHTYPE_SHA160_160,
		CS_HASHTYPE_SHA256_160,
		CS_HASHTYPE_SHA256_256,
		CS_HASHTYPE_SHA384_384,
	};
	// Define the rank of the code directory as its index in the array plus one.
	uint8_t type = cd->hashType;
	for (unsigned i = 0; i < sizeof(rankedHashTypes) / sizeof(rankedHashTypes[0]); i++) {
		if (rankedHashTypes[i] == type) {
			return (i + 1);
		}
	}
	return 0;
}

int superblob_find_cdflags_and_team_id(const CS_SuperBlob *superblob, off_t *cdflagsOffOut, off_t *teamIDOffOut)
{
	const uint8_t *base = (const uint8_t *)superblob;
	uint32_t superLen  = OSSwapBigToHostInt32(superblob->length);
	uint32_t count      = OSSwapBigToHostInt32(superblob->count);
 
	size_t indexBytes = (size_t)count * sizeof(CS_BlobIndex);
	if (superLen < sizeof(CS_SuperBlob) || indexBytes > superLen - sizeof(CS_SuperBlob)) {
		return -1;
	}
	
	// Find best ranked code directory
	const CS_BlobIndex *bestCdIndex = NULL;
	int bestCdRank = 0;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t type     = OSSwapBigToHostInt32(superblob->index[i].type);
		uint32_t cdOffset = OSSwapBigToHostInt32(superblob->index[i].offset);
 
		if (type == CSSLOT_CODEDIRECTORY || ((CSSLOT_ALTERNATE_CODEDIRECTORIES <= type && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT))) {
			if (cdOffset > superLen || superLen - cdOffset < sizeof(CS_CodeDirectory)) {
				return -1;
			}

			const CS_CodeDirectory *cd = (const CS_CodeDirectory *)(base + cdOffset);
			if (OSSwapBigToHostInt32(cd->magic) == CSMAGIC_CODEDIRECTORY) {
				int cdRank = code_directory_rank(cd);
				if (cdRank > bestCdRank) {
					bestCdIndex = &superblob->index[i];
					bestCdRank = cdRank;
				}
			}
		}
	}
	if (!bestCdIndex) return -1;

	*cdflagsOffOut = (off_t)OSSwapBigToHostInt32(bestCdIndex->offset) + (off_t)offsetof(CS_CodeDirectory, flags);
	if (teamIDOffOut) {
		uint32_t version = *(uint32_t *)((uintptr_t)superblob + (off_t)OSSwapBigToHostInt32(bestCdIndex->offset) + (off_t)offsetof(CS_CodeDirectory, version));
		*teamIDOffOut = (version >= 0x20200) ? ((off_t)OSSwapBigToHostInt32(bestCdIndex->offset) + (off_t)offsetof(CS_CodeDirectory, teamOffset)) : 0;
	}
	return 0;
}

bool superblob_is_adhoc_signed(const CS_SuperBlob *superblob)
{
	if (!superblob) return false;
	const uint8_t *base = (const uint8_t *)superblob;
	uint32_t superMagic = OSSwapBigToHostInt32(superblob->magic);
	if (superMagic != CSMAGIC_EMBEDDED_SIGNATURE &&
	    superMagic != CSMAGIC_DETACHED_SIGNATURE) return false;
	uint32_t superLen  = OSSwapBigToHostInt32(superblob->length);
	uint32_t count      = OSSwapBigToHostInt32(superblob->count);
 
	size_t indexBytes = (size_t)count * sizeof(CS_BlobIndex);
	if (superLen < sizeof(CS_SuperBlob) || indexBytes > superLen - sizeof(CS_SuperBlob)) {
		return false;
	}
	
	// Find signature slot
	const CS_GenericBlob *wrapperBlob = NULL;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t type     = OSSwapBigToHostInt32(superblob->index[i].type);
		uint32_t cdOffset = OSSwapBigToHostInt32(superblob->index[i].offset);
 
		if (type == CSSLOT_SIGNATURESLOT) {
			// CMS wrappers have an eight-byte header, not a full CodeDirectory.
			// Treat an invalid slot as malformed rather than assuming ad-hoc.
			if (cdOffset < sizeof(CS_SuperBlob) + indexBytes ||
			    cdOffset > superLen ||
			    superLen - cdOffset < sizeof(CS_GenericBlob)) {
				return false;
			}

			wrapperBlob = (const CS_GenericBlob *)((uintptr_t)superblob + cdOffset);
			break;
		}
	}

	if (wrapperBlob) {
		uint32_t wrapperLen = OSSwapBigToHostInt32(wrapperBlob->length);
		uint32_t wrapperOffset = (uint32_t)((const uint8_t *)wrapperBlob - base);
		if (OSSwapBigToHostInt32(wrapperBlob->magic) != CSMAGIC_BLOBWRAPPER ||
		    wrapperLen < sizeof(CS_GenericBlob) ||
		    wrapperLen > superLen - wrapperOffset) return false;
		return wrapperLen == sizeof(CS_GenericBlob);
	}

	return true;
}

// Resolved by main.S's MachOMerger trampoline. Private dyldhook is built
// self-contained: writing to errno would import ___error from libSystem.
extern int cerror(int error);

static int fcntl_trust_error(int status)
{
	// Do not report success to dyld after a trust/attach failure. Retain
	// a useful POSIX error via dyld's existing cerror trampoline, not errno.
	int error = EIO;
	switch (status) {
		case KERN_INVALID_ARGUMENT: error = EINVAL; break;
		case KERN_PROTECTION_FAILURE: error = EACCES; break;
		case KERN_NO_SPACE:
		case KERN_RESOURCE_SHORTAGE: error = ENOMEM; break;
		case MACH_SEND_TIMED_OUT:
		case MACH_RCV_TIMED_OUT: error = ETIMEDOUT; break;
		case MACH_SEND_INVALID_DEST:
		case MACH_RCV_PORT_DIED: error = EPIPE; break;
	}
	return cerror(error);
}

int HOOK(__fcntl)(int fd, int cmd, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7, void *arg8)
{
	// Disable LV bypass if this process does not have a bootstrap port
	// But only if the process is also running in safe mode

	// We do not want to apply the LV bypass if injection into this process is disabled and it doesn't have a bootstrap port
	// This fixes the following things
	// - Driverkit processes crash looping
	//   (They will crash when trying to contact launchdhook over the port obtained from mach_ports_lookup)
	// - The system deadlocking during early boot

	if (jbinfo_is_checked_in() || proc_has_bootstrap_port()) {
		switch (cmd) {
			case F_ADDSIGS:
					// Older dyld's in-memory signature does not require a RootHide
					// rewrite except on TXM devices that force CS_ADHOC.
					if (!jbinfo_should_force_cs_adhoc()) break;
					__attribute__((fallthrough));
			case F_ADDFILESIGS:
				case F_ADDFILESIGS_INFO:
			case F_ADDFILESIGS_RETURN: {
					// First give the kernel its normal signature attach. In
					// particular, never synthesize the RETURN/INFO output fields.
					if (cmd != F_ADDSIGS) {
						int result = (int)msyscall_errno(0x5C, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
						if (result == 0 || !jbinfo_is_checked_in()) return result;
					}
					struct siginfo siginfo = {0};
				siginfo.source = (cmd == F_ADDSIGS) ? SIGNATURE_SOURCE_PROC : SIGNATURE_SOURCE_FILE;
				if (arg1) {
						memcpy(&siginfo.signature, arg1, offsetof(fsignatures_t, fs_fsignatures_size));

					if (jbinfo_should_force_cs_adhoc()) {
						// Do whatever is neccessary to support non CS_ADHOC signed libraries on TXM devices
						// This isn't pretty, but it has to be done

						bool isFinished = false;
						int r = 0;

							bool isFile = (cmd != F_ADDSIGS);
						bool superblobNeedsFree = false;

						CS_SuperBlob *superblob = NULL;
						if (isFile) {
							off_t orgPos = lseek(fd, 0, SEEK_CUR);
							superblob = load_signature(fd, &siginfo.signature);
							lseek(fd, orgPos, SEEK_SET);
							superblobNeedsFree = true;
						}
						else {
								if (siginfo.signature.fs_blob_start &&
								    siginfo.signature.fs_blob_size >= sizeof(CS_SuperBlob)) {
									superblob = (CS_SuperBlob *)siginfo.signature.fs_blob_start;
									uint32_t size = OSSwapBigToHostInt32(superblob->length);
									if (size < sizeof(CS_SuperBlob) ||
									    size > siginfo.signature.fs_blob_size) superblob = NULL;
								}
						}

						if (superblob) {
							if (superblob_is_adhoc_signed(superblob)) {
								off_t cdFlagsOffset = 0;
								off_t teamIdOffset = 0;
								if (superblob_find_cdflags_and_team_id(superblob, &cdFlagsOffset, &teamIdOffset) == 0) {
									bool hasTeamId = false;
									if (teamIdOffset) {
										uint32_t *teamOffsetPtr = (uint32_t *)((uintptr_t)superblob + teamIdOffset);
										hasTeamId = (bool)OSSwapBigToHostInt32(*teamOffsetPtr);
									}

									uint32_t *cdFlagsPtr = (uint32_t *)((uintptr_t)superblob + cdFlagsOffset);
									if (!!(OSSwapBigToHostInt32(*cdFlagsPtr) & CS_ADHOC) == hasTeamId) {
										// According to TXM, either CS_ADHOC or TeamID is fine
										// Both or neither are not
										// Neither: We give it CS_ADHOC
										// Both: We strip CS_ADHOC

										if (!isFile) {
											// If coming from F_ADDSIGS, it could be that the signature is mapped read-only
											// To ensure it is read write (so we can add CS_ADHOC), we need to copy it
											vm_address_t addr = 0;
											if (vm_allocate(mach_task_self(), &addr, siginfo.signature.fs_blob_size, VM_FLAGS_ANYWHERE) == 0) {
												memcpy((void *)addr, superblob, OSSwapBigToHostInt32(superblob->length));
												superblob = (CS_SuperBlob *)addr;
												superblobNeedsFree = true;
											}
										}

										if (superblobNeedsFree) {
											// If we don't have a copy of the superblob at this point, all bets are off
											cdFlagsPtr = (uint32_t *)((uintptr_t)superblob + cdFlagsOffset);

											if (hasTeamId) {
												// Has both TeamID and CS_ADHOC, strip CS_ADHOC
												*cdFlagsPtr &= ~(OSSwapHostToBigInt32(CS_ADHOC));
											}
											else {
												// Has neither TeamID or CS_ADHOC, add CS_ADHOC
												*cdFlagsPtr |= OSSwapHostToBigInt32(CS_ADHOC);
											}

											siginfo.source = SIGNATURE_SOURCE_PROC;
											siginfo.signature.fs_blob_start = (void *)superblob;

											// Get everything done here: Trust modified signature and attach it
											r = jbclient_mach_trust_file(fd, &siginfo, true);
											isFinished = true;
										}
									}
								}
							}

							if (superblobNeedsFree) {
								vm_deallocate(mach_task_self(), (vm_address_t)superblob, siginfo.signature.fs_blob_size);
							}
						}

						if (isFinished) {
									if (r != 0) return fcntl_trust_error(r);
					if (cmd == F_ADDFILESIGS_RETURN || cmd == F_ADDFILESIGS_INFO) {
										return (int)msyscall_errno(0x5C, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
									}
									return 0;
						}
					}
				}

				jbclient_mach_trust_file(fd, arg1 ? &siginfo : NULL, false);
				break;
			}
		}
	}

	return (int)msyscall_errno(0x5C, fd, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}
