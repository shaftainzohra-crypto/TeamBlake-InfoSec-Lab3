import requests
import time
import statistics
import random
import argparse

TAG_LENGTH = 12
BYTE_VALUES = list(range(256))
URL = "https://interrato.dev/infosec/variabletime"
TIMEOUT_SECONDS = 10
MAX_RETRIES = 8
REQUEST_PAUSE_SECONDS = 0.03
ROUGH_SAMPLES = 4
REFINE_ROUNDS = 16
TOP_CANDIDATES = 8
CHECKPOINT_FILE = "Task6-recovered.txt"

session = requests.Session()



# ---------- Timing Attack Helper Functions ----------
# Store the recovered prefix so the attack can be resumed without starting
# again from the first byte.
def save_checkpoint(known_prefix):
    with open(CHECKPOINT_FILE, "w", encoding="ascii") as checkpoint:
        checkpoint.write(known_prefix.hex() + "\n")


def load_checkpoint():
    try:
        with open(CHECKPOINT_FILE, "r", encoding="ascii") as checkpoint:
            return bytes.fromhex(checkpoint.read().strip())
    except FileNotFoundError:
        return b""


# Making my life a bit easier by allowing prefixes to be specified directly on the command line.
# This is useful for testing and for resuming the attack from a specific point.
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--message", default="Team Blake")
    parser.add_argument("--prefix", default=None, help="Recovered tag prefix in hex")
    parser.add_argument("--resume", action="store_true", help=f"Resume from {CHECKPOINT_FILE}")
    return parser.parse_args()


def verify_tag(message, tag):
    valid, _ = query_oracle(message, tag)
    return valid


def classify_response(response, tag_param):
    response_text = response.text.strip().lower()

    if response.status_code == 418:
        return False
    if "invalid tag" in response_text or "error:" in response_text:
        return False
    if "valid tag" in response_text or "success" in response_text:
        return True

    # I found out the endpoint returns its normal HTML page with HTTP 200 for a successful
    # full-length forgery. It does not necessarily include the word "valid".
    # Still not sure this is the best way to handle this, but it works for now.
    if response.status_code == 200 and len(tag_param) == TAG_LENGTH * 2:
        return True

    return None



# ---------- Oracle Query Function ----------
def query_oracle(message, tag):
    tag_param = tag.hex() if isinstance(tag, bytes) else tag
    params = {
        "message": message,
        "tag": tag_param
    }

    for attempt in range(1, MAX_RETRIES + 1):
        start_time = time.perf_counter()
        try:
            response = session.get(URL, params=params, timeout=TIMEOUT_SECONDS)
        except requests.exceptions.RequestException:
            print(f"Network error. Retrying ({attempt}/{MAX_RETRIES})...")
            time.sleep(backoff_delay(attempt))
            continue

        end_time = time.perf_counter()
        elapsed_time = end_time - start_time

        if response.status_code == 429:
            print(f"Rate limited. Retrying ({attempt}/{MAX_RETRIES})...")
            time.sleep(backoff_delay(attempt, base=1.5))
            continue

        valid = classify_response(response, tag_param)
        if valid is not None:
            time.sleep(REQUEST_PAUSE_SECONDS)
            return valid, elapsed_time

        print(
            f"Unexpected response {response.status_code}: "
            f"{response.text[:80]!r}. Retrying ({attempt}/{MAX_RETRIES})..."
        )
        time.sleep(backoff_delay(attempt))

    raise RuntimeError("Oracle did not return a usable response after several retries")


# Compute exponential backoff with random jitter to handle rate limiting
# and transient network errors more gracefully.
def backoff_delay(attempt, base=0.5):
    return min(20, base * (2 ** (attempt - 1))) + random.uniform(0, 0.5)



# ---------- Byte Recovery Function ----------
def recover_single_byte(message, known_prefix, position):
    """
    Recover one byte of the truncated HMAC tag using a timing side channel.

    The function assumes that the server compares the received tag with the
    correct one byte by byte and stops at the first mismatch. Therefore, a
    candidate byte that extends the correct prefix should produce a slightly
    longer response time. Since network timings are noisy, candidates are first
    ranked using a rough median-based scan and then the best ones are measured
    again in a refinement phase.
    """

    rough_scores = {}

    for candidate_byte in random.sample(BYTE_VALUES, len(BYTE_VALUES)):
        candidate_tag = known_prefix + bytes([candidate_byte]) + bytes(TAG_LENGTH - position - 1)
        # Query the oracle multiple times for the same candidate byte.
        # A single measurement would be too noisy in a remote timing attack
        timings = []
        for _ in range(ROUGH_SAMPLES):
            valid, elapsed_time = query_oracle(message, candidate_tag)
            if valid:
                return candidate_byte
            timings.append(elapsed_time)

        rough_scores[candidate_byte] = statistics.median(timings)

    top_candidates = sorted(rough_scores, key=rough_scores.get, reverse=True)[:TOP_CANDIDATES]
    print(f"Top candidates for byte {position + 1}: {[hex(candidate) for candidate in top_candidates]}")

    # In this phase we refine the timing measurements only for the best candidates.
    # This avoids spending too many requests on clearly bad candidates.
    refined_timings = {candidate_byte: [] for candidate_byte in top_candidates}

    for round_number in range(REFINE_ROUNDS):
        for candidate_byte in random.sample(top_candidates, len(top_candidates)):
            candidate_tag = known_prefix + bytes([candidate_byte]) + bytes(TAG_LENGTH - position - 1)
            valid, elapsed_time = query_oracle(message, candidate_tag)
            if valid:
                return candidate_byte
            refined_timings[candidate_byte].append(elapsed_time)
        if (round_number + 1) % 4 == 0:
            best_so_far = sorted(
                refined_timings,
                key=lambda candidate: statistics.median(refined_timings[candidate]),
                reverse=True
            )[:3]
            print(
                f"Refine round {round_number + 1}/{REFINE_ROUNDS}, "
                f"best so far: {[hex(candidate) for candidate in best_so_far]}"
            )

    # As final decision, we compute the refined median timing for each surviving
    # candidate and choose the one with the highest median response time.
    refined_scores = {
        candidate_byte: statistics.median(timings)
        for candidate_byte, timings in refined_timings.items()
    }

    best_byte = max(refined_scores, key=refined_scores.get)
    return best_byte



# ---------- Timing Attack Function ----------
def timed_attack(message, known_prefix=b""):
    if len(known_prefix) > TAG_LENGTH:
        raise ValueError("Known prefix is longer than the tag")

    for position in range(len(known_prefix), TAG_LENGTH):
        print(f"Recovering byte {position + 1}/{TAG_LENGTH}...")
        recovered_byte = recover_single_byte(message, known_prefix, position)
        known_prefix += bytes([recovered_byte])
        print(f"Recovered prefix: {known_prefix.hex()}")
        save_checkpoint(known_prefix)

    return known_prefix.hex()



# ---------- Main Execution ----------
if __name__ == "__main__":
    args = parse_args()
    message = args.message
    if args.prefix is not None:
        known_prefix = bytes.fromhex(args.prefix)
    elif args.resume:
        known_prefix = load_checkpoint()
    else:
        known_prefix = b""

    if known_prefix:
        print(f"Starting from known prefix: {known_prefix.hex()}")

    tag = timed_attack(message, known_prefix)
    print(f"Recovered tag: {tag}")

    valid = verify_tag(message, tag)
    if valid:
        print("Forged tag found!")
        print(f"Message: {message}")
        print(f"Tag: {tag}")
    else:
        print("Failed to forge a valid tag!")
