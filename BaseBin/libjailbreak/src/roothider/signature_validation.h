#ifndef RH3_SIGNATURE_VALIDATION_H
#define RH3_SIGNATURE_VALIDATION_H

#include <stdbool.h>
#include <stdint.h>
#include <choma/CodeDirectory.h>

// Validate the allocation and embedded CodeDirectory layout before passing
// an untrusted SuperBlob to ChOma's decoder.
bool rh3_signature_blob_is_well_formed(const CS_SuperBlob *superblob,
                                      uint32_t availableSize);

#endif
