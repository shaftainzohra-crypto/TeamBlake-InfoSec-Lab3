"""
Task 5 — Implement HMAC as defined in FIPS 198-1
Laboratory Session 3: Authentication and Integrity Protection

This module implements the Keyed-Hash Message Authentication Code (HMAC)
as specified in FIPS 198-1. Both a standard (all-at-once) version and a
streaming (chunked-update) version are provided using a class-based design.

References:
    - FIPS 198-1: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
    - FIPS 180-4: SHA-2 family specifications
"""

import hashlib          # Python's built-in hash library (used as the underlying H)
import hmac as _hmac    # Python's built-in HMAC (used ONLY for interoperability tests)
import os               # For secure random byte generation in tests
import time             # For timing benchmarks
import secrets          # Cryptographically secure random number generation


# ---------------------------------------------------------------------------
# FIPS 198-1 constants
# ---------------------------------------------------------------------------
IPAD_BYTE = 0x36   # Inner padding byte (ipad = byte 0x36 repeated B times)
OPAD_BYTE = 0x5C   # Outer padding byte (opad = byte 0x5C repeated B times)


def _resolve_hash(hash_name: str):
    """
    Return (constructor_fn, block_size_B, digest_size_L) for a SHA-2 variant.

    FIPS 198-1 Section 3 defines B (block size) and L (output size) for each hash.
    The block size B determines how the key K is padded or truncated to form K0.
    """
    SUPPORTED = {
        "sha224":     (lambda: hashlib.new("sha224"),     64,  28),
        "sha256":     (lambda: hashlib.new("sha256"),     64,  32),
        "sha384":     (lambda: hashlib.new("sha384"),    128,  48),
        "sha512":     (lambda: hashlib.new("sha512"),    128,  64),
        "sha512_224": (lambda: hashlib.new("sha512_224"),128,  28),
        "sha512_256": (lambda: hashlib.new("sha512_256"),128,  32),
    }
    key = hash_name.lower().replace("-", "_").replace("/", "_")
    if key not in SUPPORTED:
        raise ValueError(f"Unsupported hash '{hash_name}'. Supported: {list(SUPPORTED)}")
    return SUPPORTED[key]


class HMAC:
    """
    Standard HMAC per FIPS 198-1.

    FIPS 198-1 Algorithm:
        Given: K (key), text (message), H (hash function)
        B  = block size of H in bytes
        L  = output size of H in bytes
        ipad = 0x36 repeated B times
        opad = 0x5C repeated B times

        1. Derive K0 (B-byte key):
             len(K) == B  =>  K0 = K
             len(K) >  B  =>  K0 = H(K) || 0x00^(B-L)
             len(K) <  B  =>  K0 = K    || 0x00^(B-len(K))
        2. Si = K0 XOR ipad
        3. So = K0 XOR opad
        4. HMAC = H(So || H(Si || text))
    """

    def __init__(self, key: bytes, msg: bytes = b"", hash_name: str = "sha256"):
        """
        Initialise the HMAC object and absorb any initial message bytes.

        Args:
            key       : Secret key K (any byte-string length accepted).
            msg       : Optional first message chunk (may be empty).
            hash_name : SHA-2 algorithm name (default: 'sha256').
        """
        # Resolve hash constructor and FIPS-defined parameters B and L
        constructor, block_size, digest_size = _resolve_hash(hash_name)
        self._constructor = constructor    # Creates a fresh hash object when called
        self._block_size  = block_size     # B: block size in bytes (64 or 128)
        self._digest_size = digest_size    # L: HMAC output length in bytes
        self._hash_name   = hash_name      # Kept for repr and copy()

        # ── Step 1: derive the normalised B-byte key K0 ─────────────────────
        if len(key) > block_size:
            # Key is longer than one block: hash it to reduce to L bytes
            h = constructor()              # Fresh hash object
            h.update(key)                  # Absorb the raw over-length key
            key = h.digest()              # key is now L bytes (L <= B always)
        # Zero-pad to exactly B bytes (handles both len<B and the hashed case)
        self._K0 = key.ljust(block_size, b"\x00")  # K0 is always exactly B bytes

        # ── Steps 2 & 3: compute Si (inner) and So (outer) padded keys ──────
        self._Si = bytes(k ^ IPAD_BYTE for k in self._K0)  # K0 XOR ipad, byte-by-byte
        self._So = bytes(k ^ OPAD_BYTE for k in self._K0)  # K0 XOR opad, byte-by-byte

        # ── Step 4 (inner part): start computing H(Si || text) ──────────────
        self._inner = constructor()        # Hash object that will compute inner digest
        self._inner.update(self._Si)       # Feed Si first; text will follow via update()

        # Absorb the optional initial message chunk if provided
        if msg:
            self._inner.update(msg)        # Append to Si in the inner hash state

        # Guard: prevent update() after digest() has been called
        self._finalised = False

    def update(self, msg: bytes) -> "HMAC":
        """
        Absorb additional message bytes into the running inner hash state.

        Mirrors the hashlib interface, enabling piecewise / streaming use.

        Args:
            msg: Next chunk of message bytes.
        Returns:
            self (enables method chaining: hmac.update(a).update(b))
        """
        if self._finalised:
            raise RuntimeError("Cannot call update() after digest() has been called.")
        self._inner.update(msg)            # Append chunk to H(Si || … )
        return self                        # Return self for chaining

    def digest(self) -> bytes:
        """
        Finalise and return the raw HMAC tag (L bytes).

        FIPS 198-1 Step 4: HMAC = H(So || H(Si || text))
        """
        self._finalised = True

        inner_hash = self._inner.digest()  # Finalise inner hash: H(Si || text)

        outer = self._constructor()        # New hash object for the outer layer
        outer.update(self._So)            # Feed the outer padded key So
        outer.update(inner_hash)          # Feed the inner digest H(Si || text)
        return outer.digest()             # Final tag: H(So || inner_hash)

    def hexdigest(self) -> str:
        """Return the HMAC tag as a lowercase hexadecimal string."""
        return self.digest().hex()

    def copy(self) -> "HMAC":
        """
        Return a deep copy of the current HMAC state.

        Allows processing a common prefix once and then branching into
        multiple independent HMAC computations without re-feeding data.
        """
        import copy
        return copy.deepcopy(self)         # Deep-copy keeps the hash object state

    def __repr__(self) -> str:
        return (
            f"HMAC(hash={self._hash_name!r}, "
            f"block_size={self._block_size}B, "
            f"digest_size={self._digest_size}B)"
        )


class StreamingHMAC:
    """
    Streaming HMAC implementation (Challenge — Task 5).

    Makes the streaming contract explicit: data is fed in arbitrary-size
    chunks via feed(), and the final tag is produced by finalise().
    No buffering overhead: the underlying hash natively supports streaming.

    Memory usage is O(1) in message size — only one hash state is held.
    """

    def __init__(self, key: bytes, hash_name: str = "sha256"):
        """
        Initialise the streaming HMAC engine.

        Args:
            key       : Secret key (any length; normalisation handled internally).
            hash_name : Underlying hash algorithm (default: 'sha256').
        """
        # Delegate all key setup to the base HMAC class (no initial message)
        self._hmac       = HMAC(key, b"", hash_name)  # HMAC engine ready for updates
        self._hash_name  = hash_name                   # Stored for repr
        self._byte_count = 0                           # Diagnostic byte counter
        self._done       = False                       # Prevent double-finalisation

    def feed(self, chunk: bytes) -> "StreamingHMAC":
        """
        Push the next chunk of message bytes into the HMAC computation.

        Args:
            chunk: Arbitrary-length byte string. Empty chunks are silently ignored.
        Returns:
            self (enables chaining: sh.feed(a).feed(b))
        """
        if self._done:
            raise RuntimeError("StreamingHMAC: cannot call feed() after finalise().")
        if chunk:                              # Skip empty chunks — no-op and safe
            self._hmac.update(chunk)          # Append chunk to the inner hash
            self._byte_count += len(chunk)    # Update byte counter for diagnostics
        return self

    def feed_file(self, file_path: str, chunk_size: int = 65_536) -> "StreamingHMAC":
        """
        Stream a file through the HMAC in fixed-size blocks (default 64 KiB).

        Uses a fixed-size read buffer so memory usage is bounded regardless
        of file size. Suitable for files that do not fit in RAM.

        Args:
            file_path  : Path to the file to authenticate.
            chunk_size : Read buffer size in bytes (default 64 KiB).
        Returns:
            self
        """
        with open(file_path, "rb") as fh:    # Open in binary mode
            while True:
                chunk = fh.read(chunk_size)  # Read next block (up to chunk_size bytes)
                if not chunk:                # EOF reached
                    break
                self.feed(chunk)             # Process this block
        return self

    def finalise(self) -> bytes:
        """
        Complete the HMAC computation and return the raw tag bytes.

        This must be called exactly once; further feed() calls raise an error.

        Returns:
            HMAC tag as bytes of length L (digest size of the chosen hash).
        """
        if self._done:
            raise RuntimeError("StreamingHMAC: finalise() already called.")
        self._done = True
        return self._hmac.digest()           # Delegate final digest to the HMAC engine

    def finalise_hex(self) -> str:
        """Return the final HMAC tag as a lowercase hex string."""
        return self.finalise().hex()

    @property
    def bytes_processed(self) -> int:
        """Total message bytes fed so far (key material excluded)."""
        return self._byte_count

    def __repr__(self) -> str:
        return (
            f"StreamingHMAC(hash={self._hash_name!r}, "
            f"bytes_processed={self._byte_count})"
        )


def hmac_digest(key: bytes, msg: bytes, hash_name: str = "sha256") -> bytes:
    """
    One-shot convenience function: compute HMAC(key, msg) and return raw tag bytes.

    For large messages, prefer StreamingHMAC to avoid loading all data into memory.
    """
    return HMAC(key, msg, hash_name).digest()  # Create, absorb, finalise in one chain


class InteroperabilityTests:
    """
    Randomised interoperability tests comparing our HMAC against Python's
    built-in hmac module (stdlib), which is battle-tested and NIST-validated.

    Test philosophy (per lab guidelines):
        For randomly generated (key, message) pairs, verify our output is
        identical to the reference implementation's output.
    """

    # Mapping: our hash_name string → hashlib-accepted alias
    HASH_ALIAS = {
        "sha224":     "sha224",
        "sha256":     "sha256",
        "sha384":     "sha384",
        "sha512":     "sha512",
        "sha512_224": "sha512_224",
        "sha512_256": "sha512_256",
    }

    @staticmethod
    def _reference_hmac(key: bytes, msg: bytes, hash_name: str) -> bytes:
        """Compute HMAC using Python's stdlib hmac (the reference/oracle)."""
        alias = InteroperabilityTests.HASH_ALIAS[hash_name]
        return _hmac.new(key, msg, alias).digest()

    @staticmethod
    def run_standard_tests(
        hash_name:   str = "sha256",
        n_tests:     int = 200,
        max_key_len: int = 150,    # Spans short, exact, and long key lengths
        max_msg_len: int = 1024,   # Variable-length messages up to 1 KiB
    ) -> dict:
        """
        Run n_tests random (key, message) pairs and compare with stdlib HMAC.

        Key lengths are chosen from [1, max_key_len] to exercise all three
        normalisation branches defined in FIPS 198-1 Section 3.
        """
        passed = 0
        failed = []

        for i in range(n_tests):
            # Random key length in [1, max_key_len]: covers short/exact/long cases
            key_len = secrets.randbelow(max_key_len) + 1       # Ensure non-zero
            key     = secrets.token_bytes(key_len)             # Cryptographically random

            # Random message including empty (msg_len == 0 is valid for HMAC)
            msg_len = secrets.randbelow(max_msg_len + 1)       # [0, max_msg_len]
            msg     = secrets.token_bytes(msg_len)

            our_tag = hmac_digest(key, msg, hash_name)         # Our implementation
            ref_tag = InteroperabilityTests._reference_hmac(key, msg, hash_name)

            if our_tag == ref_tag:
                passed += 1
            else:
                # Record the full failure vector for debugging
                failed.append({
                    "index":   i,
                    "key_hex": key.hex(),
                    "msg_hex": msg.hex(),
                    "our_hex": our_tag.hex(),
                    "ref_hex": ref_tag.hex(),
                })

        return {
            "hash_name": hash_name,
            "n_tests":   n_tests,
            "passed":    passed,
            "failed":    len(failed),
            "failures":  failed,
            "pass_rate": passed / n_tests,
        }

    @staticmethod
    def run_streaming_tests(
        hash_name:     str = "sha256",
        n_tests:       int = 100,
        max_chunks:    int = 10,
        max_chunk_len: int = 200,
    ) -> dict:
        """
        Verify that StreamingHMAC (chunked feeding) matches the one-shot result.

        Each test splits the message into a random number of random-length chunks
        and verifies that feeding them piecewise gives the same tag.
        """
        passed = 0
        failed = []

        for i in range(n_tests):
            key_len  = secrets.randbelow(150) + 1               # Random key length
            key      = secrets.token_bytes(key_len)
            n_chunks = secrets.randbelow(max_chunks) + 1        # At least 1 chunk
            chunks   = [
                secrets.token_bytes(secrets.randbelow(max_chunk_len))  # Each chunk
                for _ in range(n_chunks)
            ]
            full_msg = b"".join(chunks)                          # Reassembled message

            # Streaming: feed chunks one at a time
            sh = StreamingHMAC(key, hash_name)
            for chunk in chunks:
                sh.feed(chunk)                                   # Incremental feeding
            stream_tag = sh.finalise()

            # One-shot reference on the same concatenated message
            ref_tag = hmac_digest(key, full_msg, hash_name)

            if stream_tag == ref_tag:
                passed += 1
            else:
                failed.append({"index": i, "key": key.hex()})

        return {
            "hash_name": hash_name,
            "n_tests":   n_tests,
            "passed":    passed,
            "failed":    len(failed),
            "pass_rate": passed / n_tests,
        }

    @staticmethod
    def run_key_length_tests(hash_name: str = "sha256", n_per_class: int = 50) -> dict:
        """
        Targeted test: verify each of the three key-normalisation branches
        defined in FIPS 198-1 Section 3.

        Branch 1 — Short  : len(K) < B  → zero-pad to B bytes
        Branch 2 — Exact  : len(K) == B → use K directly as K0
        Branch 3 — Long   : len(K) > B  → K0 = H(K) zero-padded to B bytes
        """
        _, B, _ = _resolve_hash(hash_name)  # Get block size B for this algorithm
        results  = {}

        # Test each branch separately for clear diagnostic output
        for label, key_range in [
            ("short_key",  (1,       B - 1)),       # len(K) strictly less than B
            ("exact_key",  (B,       B)),            # len(K) exactly equals B
            ("long_key",   (B + 1,   B + 128)),     # len(K) strictly greater than B
        ]:
            passed = 0
            for _ in range(n_per_class):
                lo, hi  = key_range
                key_len = lo if lo == hi else (secrets.randbelow(hi - lo + 1) + lo)
                key     = secrets.token_bytes(key_len)
                msg     = secrets.token_bytes(secrets.randbelow(256))

                our = hmac_digest(key, msg, hash_name)
                ref = InteroperabilityTests._reference_hmac(key, msg, hash_name)
                if our == ref:
                    passed += 1

            results[label] = {"passed": passed, "total": n_per_class}

        return results


def benchmark_throughput(
    data_sizes_mb: list = None,
    hash_name:     str  = "sha256",
    n_trials:      int  = 5,
) -> dict:
    """
    Measure MB/s throughput of our StreamingHMAC vs Python's stdlib hmac.

    Uses median of n_trials runs per data size to reduce jitter effects.

    Args:
        data_sizes_mb : Payload sizes in MiB to benchmark.
        hash_name     : Hash algorithm name.
        n_trials      : Number of timing trials per data size.
    Returns:
        Dict with 'sizes_mb', 'our_mbs', 'ref_mbs' lists.
    """
    if data_sizes_mb is None:
        data_sizes_mb = [0.25, 0.5, 1, 2, 4]

    key     = secrets.token_bytes(32)                # Fixed 256-bit key for fair comparison
    alias   = InteroperabilityTests.HASH_ALIAS[hash_name]
    results = {"sizes_mb": data_sizes_mb, "our_mbs": [], "ref_mbs": []}

    for size_mb in data_sizes_mb:
        payload = secrets.token_bytes(int(size_mb * 1024 * 1024))  # Generate payload

        # Time our StreamingHMAC implementation
        times_our = []
        for _ in range(n_trials):
            t0 = time.perf_counter()
            sh = StreamingHMAC(key, hash_name)
            sh.feed(payload)                         # One large feed (or could be chunked)
            sh.finalise()
            times_our.append(time.perf_counter() - t0)

        # Time Python's stdlib hmac
        times_ref = []
        for _ in range(n_trials):
            t0 = time.perf_counter()
            _hmac.new(key, payload, alias).digest()  # stdlib one-shot
            times_ref.append(time.perf_counter() - t0)

        # Use median to reduce noise from OS scheduling jitter
        med_our  = sorted(times_our)[n_trials // 2]
        med_ref  = sorted(times_ref)[n_trials // 2]
        results["our_mbs"].append(round(size_mb / med_our, 2))
        results["ref_mbs"].append(round(size_mb / med_ref, 2))

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("Task 5 — HMAC Implementation & Interoperability Tests")
    print("=" * 60)

    ALGORITHMS = ["sha256", "sha224", "sha384", "sha512", "sha512_224", "sha512_256"]

    print("\n[1] Randomised interoperability tests (200 vectors each)\n")
    for alg in ALGORITHMS:
        res = InteroperabilityTests.run_standard_tests(hash_name=alg, n_tests=200)
        status = "PASS" if res["failed"] == 0 else "FAIL"
        print(f"  {alg:<15} {status}  {res['passed']}/{res['n_tests']} passed")

    print("\n[2] Streaming HMAC tests (100 vectors, random chunking)\n")
    for alg in ALGORITHMS:
        res = InteroperabilityTests.run_streaming_tests(hash_name=alg, n_tests=100)
        status = "PASS" if res["failed"] == 0 else "FAIL"
        print(f"  {alg:<15} {status}  {res['passed']}/{res['n_tests']} passed")

    print("\n[3] Key-length normalisation tests (50 vectors per branch)\n")
    for alg in ALGORITHMS:
        kres = InteroperabilityTests.run_key_length_tests(hash_name=alg)
        for branch, counts in kres.items():
            ok = counts["passed"] == counts["total"]
            print(
                f"  {alg:<15} {branch:<12} "
                f"{'OK' if ok else 'FAIL'}  "
                f"{counts['passed']}/{counts['total']}"
            )

    print("\n[4] Throughput benchmark (SHA-256)\n")
    bm = benchmark_throughput(data_sizes_mb=[1], hash_name="sha256", n_trials=5)
    print(f"  Our HMAC  : {bm['our_mbs'][0]:.2f} MB/s")
    print(f"  Stdlib    : {bm['ref_mbs'][0]:.2f} MB/s")
    print("\nAll tests complete.")
