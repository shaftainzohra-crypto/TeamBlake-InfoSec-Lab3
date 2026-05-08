import json
import urllib.parse
import requests
from Task1 import SHA256
from SHA224 import SHA224
from SHA384 import SHA384
from SHA512 import SHA512
from SHA512t import SHA512_224

# ---------------------------------------------------------------------
# Task 3 — Length-extension attack against the secret-prefix MAC
# ---------------------------------------------------------------------
# The vulnerable endpoint authenticates cookie strings using the
# secret-prefix MAC construction from Task 2:
#
#       MAC(k, m) = SHA256(k || m)
#
# Because SHA-256 follows the Merkle-Damgard construction, the public
# MAC tag can be interpreted as the final internal state after hashing:
#
#       secret_key || cookie || SHA256_padding
#
# Therefore, an attacker can append extra data to the cookie and compute
# a valid forged tag without knowing the secret key.
# ---------------------------------------------------------------------

# Load the starting cookie and tag from lab3task3.json
with open("lab3task3.json", "r") as f:
    data = json.load(f)

known_cookie_urlenc = data["cookie"]
known_tag = data["tag"]

BASE_URL = "https://interrato.dev/infosec/lengthextension"
APPEND = b";admin=true"

# Decode the original URL-encoded cookie as raw bytes.
# The replacement is needed because "+" represents a space in URL encoding.
known_cookie = urllib.parse.unquote_to_bytes(
    known_cookie_urlenc.replace("+", "%20")
)


def length_extension_attack(
        known_cookie: bytes,
        known_tag: str,
        secret_len: int,
        append: bytes,
        hash: str
):
    """
    Forge a new cookie and MAC tag using a SHA-256 length-extension attack.

    Args:
        known_cookie:
            Original decoded cookie bytes.

        known_tag:
            Valid SHA-256 MAC tag for SHA256(secret_key || known_cookie).

        secret_len:
            Candidate length of the unknown secret key in bytes.

        append:
            Data to append to the cookie.

    Returns:
        forged_cookie_urlenc:
            URL-encoded forged cookie.

        forged_tag:
            Forged SHA-256 tag in hexadecimal format.
    """

    # Recover the SHA-256 internal state from the known 256-bit tag.
    # SHA-256 state consists of eight 32-bit words.
    if (hash == "256"):
        word_len = 8
        digest_len = 64
    elif(hash == "224"):
        word_len = 8
        digest_len = 56
    elif (hash == "384"):
        word_len = 16
        digest_len = 96
    elif(hash == "512" ):
        word_len = 16
        digest_len = 128
    elif(hash == "512_224"):
        word_len = 16
        digest_len = 56
    else:
        exit("invalid name for hash")
    tag_words = [
        int(known_tag[i:i + word_len], 16)
        for i in range(0, digest_len,  word_len)
    ]
    # Riempimento per i registri mancanti (padding dello stato interno)
    while len(tag_words) < 8:
        tag_words.append(0) # Inseriamo 0 per evitare l'IndexError
    # Compute the bit length of the original authenticated input:
    #       secret_key || known_cookie
    original_msg_bits = (
                                secret_len + len(known_cookie)
                        ) * 8

    # Compute SHA-256 glue padding for the unknown original message.
    # The attacker only needs the message length, not the secret key itself.
    if (hash == "256" or hash == "224"):
        k = (448 - (original_msg_bits + 1)) % 512
    elif (hash == "384" or hash == "512" or hash == "512_224"):
        k = (896 - (original_msg_bits + 1)) % 1024
    else:
        exit("invalid name for hash 1")

    glue_padding = (
            b"\x80"
            + b"\x00" * (k // 8)
            + original_msg_bits.to_bytes(word_len, "big")
    )

    # At this point, SHA-256 has already processed:
    #       secret_key || known_cookie || glue_padding
    total_processed_bits = (
            original_msg_bits
            + len(glue_padding) * 8
    )

    # Continue SHA-256 from the recovered internal state and hash only
    # the appended data. The previous length ensures correct final padding.
    if(hash == "256"):
        forged_tag = SHA256.hash_computation(
            append,
            initial_state=tag_words,
            previous_len_bits=total_processed_bits
        )
    elif(hash == "224"):
        forged_tag = SHA224.hash_computation(
            append,
            initial_state=tag_words,
            previous_len_bits=total_processed_bits
        )
    elif(hash == "384"):
        forged_tag = SHA384.hash_computation(
            append,
            initial_state=tag_words,
            previous_len_bits=total_processed_bits
        )
    elif(hash == "512"):
        forged_tag = SHA512.hash_computation(
            append,
            initial_state=tag_words,
            previous_len_bits=total_processed_bits
        )
    elif(hash == "512_224"):
        forged_tag = SHA512_224.hash_computation(
            append,
            initial_state=tag_words,
            previous_len_bits=total_processed_bits
        )
    else:
        exit("Invalid name for hash 2")
    # The forged cookie must include the glue padding explicitly, because
    # the server recomputes SHA256(secret_key || forged_cookie) from scratch.
    forged_cookie_bytes = (
            known_cookie
            + glue_padding
            + append
    )

    # URL-encode raw bytes so they can be safely sent as a query parameter.
    forged_cookie_urlenc = urllib.parse.quote_from_bytes(
        forged_cookie_bytes
    )

    return forged_cookie_urlenc, forged_tag

if __name__ == "__main__":
    print("Starting Task 3 length-extension attack...\n")

    # The secret-key length is unknown, so we brute-force reasonable candidates.
    for secret_len in range(1, 65):

        forged_cookie, forged_tag = length_extension_attack(
            known_cookie,
            known_tag,
            secret_len,
            APPEND,
            "512"
        )

        # The forged cookie is already URL-encoded.
        # Do not use requests' params argument, otherwise it will double-encode
        # the glue padding bytes.
        url = f"{BASE_URL}?cookie={forged_cookie}&tag={forged_tag}"

        try:
            response = requests.get(url, timeout=10)

            print(
                f"[secret_len={secret_len:2d}] "
                f"Status: {response.status_code} | "
                f"{response.text[:100]}"
            )

            # A 200 response means the forged cookie-tag pair was accepted.
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
