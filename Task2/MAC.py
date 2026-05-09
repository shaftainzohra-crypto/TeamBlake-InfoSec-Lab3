import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from Task1.SHA256 import SHA256

class MAC:

    def mac_computation(key_bytes,msg_bytes, hash):
            return SHA256.hash_computation(key_bytes+msg_bytes)


#test
with open("lab3task2.json", "r") as f:
    tests = json.load(f)

for test in tests:
    result = MAC.mac_computation(bytes.fromhex(test["key"]), bytes.fromhex(test["msg"]),"256")
    expected = bytes.fromhex(test["tag"])

    status = "PASS" if result == expected else "FAIL"

    print(f'Test {test["number"]}: {status}')
    if status == "FAIL":
        print(f'   Result:   {result}')
        print(f'   Expected: {expected}')

