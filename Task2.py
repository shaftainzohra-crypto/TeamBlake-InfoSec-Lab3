import json
from SHA256 import SHA256
class MAC:

    def mac_computation(key_hex,msg_hex):
        key_bytes = bytes.fromhex(key_hex)
        msg_bytes = bytes.fromhex(msg_hex)
        return SHA256.hash_computation(key_bytes+msg_bytes)

#test
with open("lab3task2.json", "r") as f:
    tests = json.load(f)
#print(MAC.mac_computation("80000000000000000000000000000000","73686f7274"))
for test in tests:
    result = MAC.mac_computation(test["key"], test["msg"])
    expected = test["tag"]

    status = "PASS" if result == expected else "FAIL"

    print(f'Test {test["number"]}: {status}')
    if status == "FAIL":
        print(f'   Result:   {result}')
        print(f'   Expected: {expected}')

