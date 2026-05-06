import json
from SHA256 import SHA256
from SHA224 import SHA224
from SHA384 import SHA384
from SHA512 import SHA512
from SHA512t import SHA512_224

class MAC:

    def mac_computation(key_hex,msg_hex, hash):
        key_bytes = bytes.fromhex(key_hex)
        msg_bytes = bytes.fromhex(msg_hex)
        if (hash == "256"):
            return SHA256.hash_computation(key_bytes+msg_bytes)
        if (hash == "224"):
            return SHA224.hash_computation(key_bytes+msg_bytes)
        if (hash == "384"):
            return SHA384.hash_computation(key_bytes+msg_bytes)
        if (hash == "512"):
            return SHA512.hash_computation(key_bytes+msg_bytes)
        if (hash == "512t"):
            return SHA512_224.hash_computation(key_bytes+msg_bytes)


#test
with open("lab3task2.json", "r") as f:
    tests = json.load(f)
#print(MAC.mac_computation("80000000000000000000000000000000","73686f7274"))
for test in tests:
    result = MAC.mac_computation(test["key"], test["msg"],"256")
    expected = test["tag"]

    status = "PASS" if result == expected else "FAIL"

    print(f'Test {test["number"]}: {status}')
    if status == "FAIL":
        print(f'   Result:   {result}')
        print(f'   Expected: {expected}')

