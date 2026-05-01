import urllib.parse
import requests
from Task1 import SHA256

# ---------------------------------------------------------------------
# Task 3 — Length-extension attack against SHA256(key || cookie)
# ---------------------------------------------------------------------

# Initial values provided in lab3task3.json
known_cookie_urlenc = "comment%3Dyou+don%27t+need+more+than+128+bits+of+symmetric+keys+for+post-quantum+security"
known_tag = "4a621734dc9558649a185a8f83d598159407391ce942e29cf11617ed83d5afeb"

BASE_URL = "https://interrato.dev/infosec/lengthextension"
APPEND = b";admin=true"

# Decode the original cookie as raw bytes.
known_cookie = urllib.parse.unquote_to_bytes(
    known_cookie_urlenc.replace("+", "%20")
)


def length_extension_attack(
    known_cookie: bytes,
    known_tag: str,
    secret_len: int,
    append: bytes
):
    """
    Forge a new cookie and MAC tag using a SHA-256 length-extension attack.

    Args:
        known_cookie: The original decoded cookie bytes.
        known_tag: The valid SHA-256 MAC tag for secret || known_cookie.
        secret_len: Candidate length of the unknown secret key in bytes.
        append: Data to append to the cookie.

    Returns:
        A tuple containing:
            - URL-encoded forged cookie
            - forged SHA-256 tag in hexadecimal format
    """

    # Recover the SHA-256 internal state from the known 256-bit tag.
    tag_words = [int(known_tag[i:i + 8], 16) for i in range(0, 64, 8)]

    # Compute the bit length of the original authenticated input:
    # secret_key || known_cookie
    original_msg_bits = (secret_len + len(known_cookie)) * 8

    # Compute SHA-256 glue padding for the unknown original message.
    # The attacker only needs the length, not the secret key itself.
    k = (448 - (original_msg_bits + 1)) % 512

    glue_padding = (
        b"\x80"
        + b"\x00" * (k // 8)
        + original_msg_bits.to_bytes(8, "big")
    )

    # At this point, SHA-256 has already processed:
    # secret_key || known_cookie || glue_padding
    total_processed_bits = original_msg_bits + len(glue_padding) * 8

    # Continue SHA-256 from the recovered internal state and hash only
    # the appended data. The previous length ensures correct final padding.
    forged_tag = SHA256.hash_computation(
        append,
        initial_state=tag_words,
        previous_len_bits=total_processed_bits
    )

    # The forged cookie must include the glue padding explicitly, because
    # the server will compute SHA256(secret_key || forged_cookie) from scratch.
    forged_cookie_bytes = known_cookie + glue_padding + append

    # URL-encode raw bytes so they can be safely sent as a query parameter.
    forged_cookie_urlenc = urllib.parse.quote_from_bytes(forged_cookie_bytes)

    return forged_cookie_urlenc, forged_tag


print("Starting Task 3 length-extension attack...\n")

# The key length is unknown, so we brute-force reasonable candidates.
for secret_len in range(1, 65):
    forged_cookie, forged_tag = length_extension_attack(
        known_cookie,
        known_tag,
        secret_len,
        APPEND
    )

    # Do not use requests' params argument here because the cookie is already
    # URL-encoded. Passing it through params would double-encode the padding.
    url = f"{BASE_URL}?cookie={forged_cookie}&tag={forged_tag}"

    try:
        response = requests.get(url, timeout=10)

        print(
            f"[secret_len={secret_len:2d}] "
            f"Status: {response.status_code} | "
            f"{response.text[:100]}"
        )

        # A 200 response indicates that the forged cookie-tag pair was accepted.
        if response.status_code == 200:
            print("\nSUCCESS")
            print("Secret length:", secret_len)
            print("Forged cookie:", forged_cookie)
            print("Forged tag:", forged_tag)
            print("Full URL:", url)
            break

    except requests.RequestException as e:
        print(f"[secret_len={secret_len:2d}] Request failed: {e}")

else:
    print("\nNo valid secret length found.")