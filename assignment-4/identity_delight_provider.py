"""
# #4 Identity Delight Provider (1-2)

## Type
Cryptography

## Vulnerability type
Malleability Attack

## Description
My customer is using this strange identity provider, where login is performed with a username-dependent password... I'm not sure I can trust it.
-
After sending a complaint to my customer, he said he has improved the security of the system, could you check if that is for real?

## Explaination
In this challenge, the server offers the option to either generate a username-password pair using RSA or verify an existing one. 
The RSA algorithm employs a 1024-bit key and uses the default public exponent of 65537.
Upon user request, the server returns the ciphertext of the flag. 
The initial step involves extracting the 'n' factor used within the current instance of the RSA algorithm. 
For this task, refer to https://crypto.stackexchange.com/questions/43583/deduce-modulus-n-from-public-exponent-and-encrypted-data
Then, a malleability attack can be executed to generate and verify a new password using a known value (g) and the ciphertext of the flag. 
Once the decrypted text is obtained, it becomes feasible to apply the reverse formula (alongside certain calculations) to derive the plaintext of the flag.
"""

import pwn

from Crypto.Util.number import long_to_bytes, GCD

from collections import Counter
from itertools import combinations
import random

def get_n(r: pwn.tubes.remote.remote):

    # Given that with 2 m, there is a 55% probability that the final n represents the true value, 
    # increasing the number of m to > 3.6 will provide nearly 100% certainty of obtaining the true n.
    # However, due to encountering "Got EOF while reading in interactive" with pwn (likely due to a buffer overflow issue), this solution only uses two values for 'm'. 
    # In case of failure, simply restart the script and retry.
    # https://crypto.stackexchange.com/questions/43583/deduce-modulus-n-from-public-exponent-and-encrypted-data

    multiples_of_n = [] # ((c_i)^2 - c'_i)

    # Considering potential buffer overflow issues, we need to avoid attempting values that result in incorrect ciphertexts to prevent wasting attempts. 
    # For instance, 9 gives a ciphertext of 0.
    ms = [3] # Keep track of saved messages

    m = 1 # Start from 2 (since 1^2 = 1 so it is useless)

    while len(multiples_of_n) < 2:
        
        m = m + 1

        # Check if m already exists
        if m in ms:
            continue
        
        # Calculate the square of m (m')
        mp = pow(m, 2)

        # Calculate the ciphertext of m
        r.sendline(b"1")
        r.recvuntil(b"> ")
        r.sendline(long_to_bytes(m))
        c = int(r.recvline_contains(b": ").decode().split(": ")[1].strip())

        # Calculate the ciphertext of m'
        r.sendline(b"1")
        r.recvuntil(b"> ")
        r.sendline(long_to_bytes(mp))
        cp = int(r.recvline_contains(b": ").decode().split(": ")[1].strip())
        
        # Save processed messages
        ms.extend([m, mp])

        # Calculate and save ((c_i)^2 - c'_i) 
        multiples_of_n.append(pow(c, 2) - cp)
    
    # Calculate every combination and then return the n with the highest frequency
    n = [GCD(combination[0], combination[1]) for combination in list(combinations(multiples_of_n, 2))]
    n = Counter(n).most_common(1)[0][0]

    return n

def malleability_attack(r: pwn.tubes.remote.remote, n: int, flag: int):

    # Default e
    e = 65537

    # Just to demonstrate that malleability works with any (more or less) random g
    # Do not use 1 since it will not generate a new ciphertext
    # 1000 is just an example, you can modify the upper bound
    g = random.randint(2,1000)

    cp = (flag * pow(g, e)) % n

    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"> ")
    r.sendline(str(cp).encode())
    m = int(r.recvline_contains(b": ").decode().split(": ")[1].strip())

    # This step is crucial: use m // g instead of int(m / g) (decimal results from division can lead to issues later on)
    flag = long_to_bytes(m // g).decode()

    return flag

if __name__ == "__main__":

    r = pwn.remote("cyberchallenge.disi.unitn.it", 50302) # For the advanced challenge, use port 50303

    # Retrieve the ciphertext of the flag
    flag = int(r.recvline_contains(b": ").decode().split(": ")[1].strip())

    # "Guess" n
    n = get_n(r=r)

    # Perform a malleability attack on the ciphertext of the flag
    flag = malleability_attack(r=r, n=n, flag=flag)

    print(flag)