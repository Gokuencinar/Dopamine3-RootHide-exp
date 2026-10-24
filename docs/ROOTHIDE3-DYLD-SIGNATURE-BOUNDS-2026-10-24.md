# Private dyld signature-reader bounds (post-r204 work)

## Scope and trigger

The r198 physical APT HTTP method failed while loading the bundled libgnutls.
The original APT method explicitly contains LC_RPATH entries for
@loader_path/.jbroot/usr/lib and @loader_path/.jbroot/usr/local/lib.
Consequently, the nested methods/.jbroot search result is expected from
the Mach-O itself, not standalone proof of an incorrect dyld rewrite.
Both the original HTTP method and libgnutls have CS_ADHOC CodeDirectory
flags; their packaged signatures pass the host page-hash verification.
This supports visiting libgnutls in recursive trust, but does not establish
the installed binary's current signature or kernel trustcache state.
For the two files examined, all bundled @rpath dependencies are listed in
the original 1900 bootstrap; the current dyld error is not, by itself,
evidence that one of those dependent packages is missing from that archive.
RootHide reads a Mach-O code signature during private dyld's fcntl fallback.
Previously load_signature allocated fs_blob_size before validating size,
file bounds, or SuperBlob magic. The CMS wrapper classifier also mistook a
malformed wrapper for a valid ad-hoc signature.

## Changes

- Reject null, undersized, negative, overflowing or oversized signature
  positions and lengths without allocating. Check the opened file size
  through existing lseek, restoring the original offset before the read.
- Verify SuperBlob magic, declared length and index bounds.
- Reject invalid CMS wrapper magic, size or location rather than
  incorrectly reclassifying a signed binary as ad-hoc.
- Guard the in-memory F_ADDSIGS path against null or undersized blobs.
- Propagate a real trustcache upload failure from libjailbreak's
  trust_signatures function and skip signature attachment on that failure,
  rather than reporting a misleading success.

The private dyld stays self-contained: no new imported symbol, unrestricted
trust policy, elevated entitlement, process-wide bypass or synchronous
PID1 XPC call is introduced.

## Reproduction and limits

tools/tests/test_roothide_dyld_signature_bounds.py compiles the actual C
helpers against bounded host Mach stubs. It first failed at C check #3
before the patch on a four-byte signature allocation. The expanded
test now passes positive and adversarial malformed cases. The new
test_roothide_trustcache_upload_result.py compiles the production
trust_signatures tail and exercises trustcache upload failure, signature
attach failure and success; it failed at native check #1 before correction.

This does not show that the installed r198 libgnutls was corrupted, that
iOS kernel trustcache accepts the patched file, or that APT, TweakLoader
and managers actually run. Native CI and later authorized physical tests
are essential. Maintain readiness strictly at 7/9.
