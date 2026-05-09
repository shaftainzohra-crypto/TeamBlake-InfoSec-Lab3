import secrets
from MAC_parametrized import MAC
from Task3_parametrized import length_extension_attack
import urllib.parse
secret_keys = []
messages = []

for i in range(100):
    secret_keys.append(secrets.token_bytes(16))
    messages.append(secrets.token_bytes(20))

tags256 = []
tags224 = []
tags384 = []
tags512 = []
tags512_224 = []

for i in range(100):
    tags256.append(MAC.mac_computation(secret_keys[i],messages[i],"256"))
for i in range(100):
    tags224.append(MAC.mac_computation(secret_keys[i],messages[i],"224"))
for i in range(100):
    tags384.append(MAC.mac_computation(secret_keys[i],messages[i],"384"))
for i in range(100):
    tags512.append(MAC.mac_computation(secret_keys[i],messages[i],"512"))
for i in range(100):
    tags512_224.append(MAC.mac_computation(secret_keys[i],messages[i],"512_224"))

counter_256 = 0
counter_224 = 0
counter_384 = 0
counter_512 = 0
counter_512_224 = 0


APPEND = b";admin=true"
for i in range(100):
    for secret_len in range(1, 65):

        forged_message, forged_tag = length_extension_attack(
            messages[i],
            tags256[i],
            secret_len,
            APPEND,
            "256"
        )
        forged_msg_bytes = urllib.parse.unquote_to_bytes(forged_message)
        expected_tag = MAC.mac_computation(secret_keys[i],forged_msg_bytes,"256")
        if(forged_tag == expected_tag):
            counter_256 = counter_256 + 1
            break
print("Length extension attack against SHA256: success rate = " + str(counter_256) + "/100")
for i in range(100):
    for secret_len in range(1, 65):

        forged_message, forged_tag = length_extension_attack(
            messages[i],
            tags224[i],
            secret_len,
            APPEND,
            "224"
        )
        forged_msg_bytes = urllib.parse.unquote_to_bytes(forged_message)
        expected_tag = MAC.mac_computation(secret_keys[i],forged_msg_bytes,"224")
        if(forged_tag == expected_tag):
            counter_224 = counter_224 + 1
            break
print("Length extension attack against SHA224: success rate = " + str(counter_224) + "/100")
for i in range(100):
    for secret_len in range(1, 65):

        forged_message, forged_tag = length_extension_attack(
            messages[i],
            tags384[i],
            secret_len,
            APPEND,
            "384"
        )
        forged_msg_bytes = urllib.parse.unquote_to_bytes(forged_message)
        expected_tag = MAC.mac_computation(secret_keys[i],forged_msg_bytes,"384")
        if(forged_tag == expected_tag):
            counter_384 = counter_384 + 1
            break
print("Length extension attack against SHA384: success rate = " + str(counter_384) + "/100")
for i in range(100):
    for secret_len in range(1, 65):

        forged_message, forged_tag = length_extension_attack(
            messages[i],
            tags512[i],
            secret_len,
            APPEND,
            "512"
        )
        forged_msg_bytes = urllib.parse.unquote_to_bytes(forged_message)
        expected_tag = MAC.mac_computation(secret_keys[i],forged_msg_bytes,"512")
        if(forged_tag == expected_tag):
            counter_512 = counter_512 + 1
            break
print("Length extension attack against SHA512: success rate = " + str(counter_512) + "/100")
for i in range(100):
    for secret_len in range(1, 65):

        forged_message, forged_tag = length_extension_attack(
            messages[i],
            tags512_224[i],
            secret_len,
            APPEND,
            "512_224"
        )
        forged_msg_bytes = urllib.parse.unquote_to_bytes(forged_message)
        expected_tag = MAC.mac_computation(secret_keys[i],forged_msg_bytes,"512_224")
        if(forged_tag == expected_tag):
            counter_512_224 = counter_512_224 + 1
            break
print("Length extension attack against SHA512/224: success rate = " + str(counter_512_224) + "/100")





