import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from Task1.SHA256 import SHA256
from SHA224 import SHA224
from SHA384 import SHA384
from SHA512 import SHA512
from SHA512t import SHA512_224

class MAC:

    def mac_computation(key_bytes,msg_bytes, hash):
        if (hash == "256"):
            return SHA256.hash_computation(key_bytes+msg_bytes)
        elif (hash == "224"):
            return SHA224.hash_computation(key_bytes+msg_bytes)
        elif (hash == "384"):
            return SHA384.hash_computation(key_bytes+msg_bytes)
        elif (hash == "512"):
            return SHA512.hash_computation(key_bytes+msg_bytes)
        elif (hash == "512_224"):
            return SHA512_224.hash_computation(key_bytes+msg_bytes)
        else:
            exit("Invalid name for hash")

