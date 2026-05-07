import hashlib
from ecdsa import NIST256p, SigningKey
from ecdsa.numbertheory import inverse_mod
"""
Task 7 — ECDSA Nonce-Reuse Attack
=================================
Attack:
If two ECDSA signatures reuse the same nonce k, they have the same r.
From two signatures with same r, we recover k, then recover private key d.
After that, we sign our own guestbook message.
"""


# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------

CURVE = NIST256p
N = CURVE.order

#team name 
GUESTBOOK_MESSAGE = "Blake 2026-05-07"
# ---------------------------------------------------------------------
# Known reused-nonce signatures from the guestbook page
# ---------------------------------------------------------------------

msg1 = b"SHA 2026-05-04"
sig1_hex = (
    "6fdb76380be80a5239088df9e37f8530e8628d464ef9c338b8e05d423f5dd311"
    "512179b3cb2aa7298ba3ca1971c7bd0cbbaee31cf0a98c31bc7d79e69aaf8173"
)

msg2 = b"HMAC 2026-05-03"
sig2_hex = (
    "6fdb76380be80a5239088df9e37f8530e8628d464ef9c338b8e05d423f5dd311"
    "9cd5631509e037bcd2d795d7b41bb89dda8878266f2846f430c937dfc885f773"
)


# ---------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------

def hash_message(message: bytes) -> int:
    """
    Hash message with SHA-256 and convert digest to integer.
    For P-256, SHA-256 output size matches the group order size.
    """
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, "big") % N


def decode_raw_signature(sig_hex: str) -> tuple[int, int]:
    """
    Decode raw ECDSA signature format:

        signature = r || s

    where r is 32 bytes and s is 32 bytes.
    """
    raw = bytes.fromhex(sig_hex)

    if len(raw) != 64:
        raise ValueError(f"Expected 64-byte signature, got {len(raw)} bytes")

    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")

    return r, s


def encode_raw_signature(r: int, s: int) -> str:
    """
    Encode r and s as 64-byte hex string.
    """
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def recover_private_key(m1: bytes, sig1: str, m2: bytes, sig2: str) -> int:
    """
    Recover ECDSA private key from two signatures that reuse the same nonce k.
    """
    r1, s1 = decode_raw_signature(sig1)
    r2, s2 = decode_raw_signature(sig2)

    if r1 != r2:
        raise ValueError("The two signatures do not reuse the same nonce: r1 != r2")

    r = r1

    h1 = hash_message(m1)
    h2 = hash_message(m2)

    # k = (h1 - h2) * (s1 - s2)^(-1) mod n
    k = ((h1 - h2) * inverse_mod((s1 - s2) % N, N)) % N

    # d = (s1 * k - h1) * r^(-1) mod n
    d = ((s1 * k - h1) * inverse_mod(r, N)) % N

    return d


def sign_message(private_key: int, message: str) -> tuple[str, str, str]:
    """
    Sign message using recovered private key.
    Returns full signature, r, and s as hex strings.
    """
    sk = SigningKey.from_secret_exponent(
        private_key,
        curve=CURVE,
        hashfunc=hashlib.sha256
    )

    sig_bytes = sk.sign_deterministic(
        message.encode(),
        hashfunc=hashlib.sha256,
        sigencode=lambda r, s, order: (
            r.to_bytes(32, "big") + s.to_bytes(32, "big")
        )
    )

    sig_hex = sig_bytes.hex()
    r, s = decode_raw_signature(sig_hex)

    r_hex = hex(r)[2:].zfill(64)
    s_hex = hex(s)[2:].zfill(64)

    return sig_hex, r_hex, s_hex


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():
    print("=" * 70)
    print("Task 7 — ECDSA Nonce-Reuse Attack")
    print("=" * 70)

    print("\n[1] Using two signatures with the same r value")

    r1, s1 = decode_raw_signature(sig1_hex)
    r2, s2 = decode_raw_signature(sig2_hex)

    print("Message 1:", msg1.decode())
    print("Message 2:", msg2.decode())
    print("r1:", hex(r1)[2:].zfill(64))
    print("r2:", hex(r2)[2:].zfill(64))

    if r1 == r2:
        print("Same r detected: nonce k was reused.")
    else:
        raise ValueError("r values are different. Attack cannot continue.")

    print("\n[2] Recovering private key...")
    d = recover_private_key(msg1, sig1_hex, msg2, sig2_hex)

    print("Recovered private key d:")
    print(hex(d)[2:].zfill(64))

    print("\n[3] Signing our guestbook message...")
    sig_hex, r_hex, s_hex = sign_message(d, GUESTBOOK_MESSAGE)

    print("\nCopy these values into the website form:")
    print("-" * 70)
    print("message:", GUESTBOOK_MESSAGE)
    print("r      :", r_hex)
    print("s      :", s_hex)
    print("-" * 70)

    print("\nFull raw signature r||s:")
    print(sig_hex)


if __name__ == "__main__":
    main()