/* RootHide port patch for pinned ChOma 7dccded6. Host-order CodeDirectory.
 * Keep memory independent of untrusted pageSize, including unpaged (0).
 */
bool code_directory_calculate_page_hash(CS_CodeDirectory *codeDir, MachO *macho, int slot, uint8_t *pageHashOut)
{
    if (!codeDir || !macho || !pageHashOut || slot < 0) return false;
    if (codeDir->pageSize != 0 && codeDir->pageSize != 12 && codeDir->pageSize != 14) return false;
    uint8_t digestSize;
    switch (codeDir->hashType) {
        case CS_HASHTYPE_SHA160_160: digestSize = 20; break;
        case CS_HASHTYPE_SHA256_160: digestSize = 20; break;
        case CS_HASHTYPE_SHA256_256: digestSize = 32; break;
        case CS_HASHTYPE_SHA384_384: digestSize = 48; break;
        default: return false;
    }
    if (codeDir->hashSize != digestSize) return false;
    uint64_t limit = codeDir->codeLimit;
    size_t streamSize = memory_stream_get_size(macho_get_stream(macho));
    if (!limit || streamSize == MEMORY_STREAM_SIZE_INVALID || limit > streamSize) return false;
    uint64_t pageSize = codeDir->pageSize ? (UINT64_C(1) << codeDir->pageSize) : limit;
    uint64_t expectedSlots = 1 + (limit - 1) / pageSize;
    if (expectedSlots != codeDir->nCodeSlots || (uint64_t)slot >= expectedSlots) return false;
    uint64_t offset = (uint64_t)slot * pageSize;
    uint64_t remaining = limit - offset;
    if (remaining > pageSize) remaining = pageSize;

    CC_SHA1_CTX sha1;
    CC_SHA256_CTX sha256;
    CC_SHA512_CTX sha384;
    int ok;
    switch (codeDir->hashType) {
        case CS_HASHTYPE_SHA160_160: ok = CC_SHA1_Init(&sha1); break;
        case CS_HASHTYPE_SHA384_384: ok = CC_SHA384_Init(&sha384); break;
        default: ok = CC_SHA256_Init(&sha256); break;
    }
    if (!ok) return false;
    uint8_t chunk[0x4000];
    uint8_t digest[48];
    while (remaining) {
        size_t count = remaining < sizeof(chunk) ? (size_t)remaining : sizeof(chunk);
        if (macho_read_at_offset(macho, offset, count, chunk) != 0) return false;
        switch (codeDir->hashType) {
            case CS_HASHTYPE_SHA160_160: ok = CC_SHA1_Update(&sha1, chunk, (CC_LONG)count); break;
            case CS_HASHTYPE_SHA384_384: ok = CC_SHA384_Update(&sha384, chunk, (CC_LONG)count); break;
            default: ok = CC_SHA256_Update(&sha256, chunk, (CC_LONG)count); break;
        }
        if (!ok) return false;
        offset += count;
        remaining -= count;
    }
    switch (codeDir->hashType) {
        case CS_HASHTYPE_SHA160_160: ok = CC_SHA1_Final(digest, &sha1); break;
        case CS_HASHTYPE_SHA384_384: ok = CC_SHA384_Final(digest, &sha384); break;
        default: ok = CC_SHA256_Final(digest, &sha256); break;
    }
    if (!ok) return false;
    memcpy(pageHashOut, digest, digestSize);
    return true;
}
