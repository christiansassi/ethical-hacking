"""
# #3 AESWT PoC

## Type
Cryptography

## Vulnerability type
Padding Oracle Attack - Bitflipping Attack

## Description
I created a new standard for web tokens called AESWT, which aims to be a successor of JWT, but faster. Try it out in this PoC program!
-
I created a new standard for web tokens called AESWT, which aims to be a successor of JWT, but faster. Try it out in this PoC program! This time we require an actual description of yourself though.

## Explaination

In this challenge, the server prompts the user for a username and a description. 
Subsequently, using AES CBC, it generates an encrypted token. 
To exploit this system, one can strategically inject the desired text by taking advantage of the XOR operation employed within the AES algorithm (Bitflipping Attack) 
and verify the validity of the compromised token using the padding oracle available through the challenge (Padding Oracle Attack).
"""

import pwn

import random
import string

def xor(a: bytearray, b: bytearray) -> bytearray:
    assert len(a) == len(b)
    return bytearray([ x ^ y for x, y in zip(a, b)])

def get_random_token(r: pwn.tubes.remote.remote) -> tuple:

    # The reason for this approach is to ensure that the username and the description cannot have identical characters in the same positions as the characters "admin" and "I am a boss"
    # since this could potentially introduce complications during the XOR operation.
    chars = string.ascii_letters + " .,;?!'\""

    username = "".join([random.choice(chars.replace(c,"")) for c in "admin"]) # Same lenght as "admin" but different chars for each position
    description = "".join([random.choice(chars.replace(c,"")) for c in "I am a boss"]) # Same length as "I am a boss" but different chars for each position

    # Supposing to be in the main menu...
    r.sendline(b"1")
    r.sendlineafter(b"> ", username.encode())
    r.sendlineafter(b"> ", description.encode())
    token = r.recvline_contains(b": ").decode().split(": ")[1].strip()
    
    return token, username, description

BLOCK_SIZE = 16

# Init the connection
r = pwn.remote("cyberchallenge.disi.unitn.it", 50300) # For the advanced challenge, use port 50301

# Retrieve a token based on a pseudo-random username and description
token, username, description = get_random_token(r=r)

# Process
token = bytearray.fromhex(token)
iv, token = token[:BLOCK_SIZE], token[BLOCK_SIZE:] # Extract the initialization vector and the encrypted token

username = b"\x00\x00\x00\x00\x00\x00" + username.encode() # desc=...
description = b"\x00\x00\x00\x00\x00" + description.encode() # &user=...
custom_token = bytearray.fromhex(description.hex() + username.hex()) # We use \x00 (null byte) to preserve the characters that are in those positions. Our intention is to modify only the specified characters

injected_token = b"\x00\x00\x00\x00\x00I am a boss\x00\x00\x00\x00\x00\x00admin" # We use \x00 (null byte) to preserve the characters that are in those positions. Our intention is to modify only the specified characters
injected_token = bytearray.fromhex(injected_token.hex())

# Create the blocks of the token

# Block 1
block1 = token[:BLOCK_SIZE] # We take the first block of the original token

# In order to retrieve from the decryption of the first block: "desc=I am a boss", we can work on the iv.
# Specifically, we define an initialization vector (iv) in such a way that when the algorithm performs the XOR operation on D(block1), it yields the original text.
# Simultaneously, the original text will be brought to \x00 as it is XORed with itself, leaving only the text contained within injected_token.
# e.g. D(block1) xor iv xor injected_token[:BLOCK_SIZE] xor custom_token[:BLOCK_SIZE]
# Where: D(block1) xor iv = "desc=..." (initial description)
# Then: "desc=..." xor injected_token[:BLOCK_SIZE] = "desc=\x00\x00..." (it is like we delete the characters of the description)
# Finally: "desc=\x00\x00..." xor custom_token[:BLOCK_SIZE] = "desc=I am a boss" (because something XORed with \x00 will give us something)
iv = xor(xor(iv, injected_token[:BLOCK_SIZE]), custom_token[:BLOCK_SIZE])

# An empty block has a size of BLOCK_SIZE, with each byte having a value of BLOCK_SIZE.
# This is because we are using PKCS7 for padding, which adds a number of bytes to ensure the block size is equal to BLOCK_SIZE,
# with each byte representing the number of missing bytes. 
# For example, in a fully empty block, we add 16 bytes because 16 bytes are missing. 
# In a block of 1 byte, we add 15 bytes with a value equal to 15, and so on.

# Block 2: empty block
# Brute force the first byte of this block to obtain either '=' or '&' by trying every value from 0 to 255.
# This enables us to distinguish between the garbage and the actual data during the split operation on the server side.
# Without brute forcing, we might encounter a scenario where the output resembles "desc=I am a boss..." followed by random characters.
# To prevent this, we specifically brute force the first byte of the second block to ensure the presence of '=' or '&', thereby facilitating the separation of the description from the random characters.
block2 = bytearray([BLOCK_SIZE for _ in range(BLOCK_SIZE)]) # Init an empty block with respect to padding rule (see PKCS7)

# Block 3
# The idea is the same: we utilize this block to determine the resulting plaintext of block4.
# By assigning token[BLOCK_SIZE:] to block4, we understand that, since CBC utilizes the previous block for decryption, it requires block1 to be accurately reconstructed (think about how the original token is built).
# Hence, we XOR block1. Moreover, aiming to achieve "admin" as the username, we XOR the original text (custom_token) with the injected one (injected_token).
# Following this approach (similar to the initialization vector), when block4 is decrypted, it undergoes XOR with block1 (a necessity to maintain the initial xor).
# Subsequently, upon obtaining the plaintext, the username value in the plaintext is initially nullified (due to self-XOR), then replaced with "admin".
block3 = bytearray(BLOCK_SIZE) # Init an empty block (full of \x00)
for i in range(BLOCK_SIZE):

    if i < len(injected_token[BLOCK_SIZE:]):
        block3[i] = block1[i] ^ injected_token[BLOCK_SIZE:][i] ^ custom_token[BLOCK_SIZE:][i]

    else: # This is necessary in order to fill the entire block since injected_token[BLOCK_SIZE:] has a lower size
        block3[i] = block1[i] ^ block3[i]

# Block 4: based on rules used for the creation of the previous block (block3)
block4 = token[BLOCK_SIZE:]

# Brute forcing phase
for i in range(256):
    block2[0] = i
    tmp_token = iv.hex() + block1.hex() + block2.hex() + block3.hex() + block4.hex()
    
    # This is the oracle since the result string will tell us if everything went ok or not
    if i == 0:
        r.sendlineafter(b"> ", b"2")
    else:
        r.sendline(b"2")

    r.sendlineafter(b"> ", tmp_token.encode())

    # If you attempt to inspect the resulting string, you will observe that the username is 'admin'. 
    # However, this doesn't function as intended because the 'i' we assign to block2 does not translate into
    # an '=' or '&', consequently compromising the description field during the decryption phase.

    result = r.recvuntil(b"> ").decode()

    # Check the presence of the flag inside the result string
    if "UniTN" in result:
        flag = result.split("\n")[0].strip()
        print(f"Flag: {flag}")
        break
