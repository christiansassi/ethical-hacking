"""
# #5 The x86 police

## Type
Reverse engineering

## Vulnerability type
There is not a precise term to pinpoint this vulnerability.
The problem is with the executable itself, which stores sensitive information using a weak method for protection.

## Description
The program isn't doing anything illegal, innit?

## Explaination
The flag is hidden inside the executable file. 
Initially, it is necessary to decompile the file using a suitable tool, such as Ghidra.
Once this is done, by examining the `entry` function, it becomes possible to identify the main function (as Ghidra itself may not recognize it solely by decompiling the code). 
In particular, the main function is labeled as `FUN_0010121d`.
Then, it can be observed that an handler function, `FUN_00101179`, is used for a sigaction.
Upon analyzing the handler function, the code reveals that the user input stored in `DAT_00104060` is XORed with 0x42, and the resulting value is then compared with `DAT_00102020`.
This implies that the XORed version of the flag resides within `DAT_00102020`, and by XORing it with 0x42, the plaintext of the flag can be obtained.
To achieve this, simply examine `DAT_00102020`, copy the bytes associated with this variable, and perform the XOR operation on them.

## Extra
For the installation and usage of pyhidra follow this guide:
https://pypi.org/project/pyhidra/
"""

import pyhidra
from os.path import isfile

def get_functions(flat_api, parent: str, func_only: bool = True) -> list:

    # After importing pyhidra and start it, this will work
    from ghidra.util.task import TaskMonitor # type: ignore
    monitor = TaskMonitor.DUMMY

    functions = []

    for function in flat_api.getFunction(parent).getCalledFunctions(monitor):

        # If the flag is enabled, extract functions with a name that starts with FUN_
        if func_only and not function.name.startswith("FUN_"):
            continue

        functions.append({
            "name": function.getName(),
            "address": "0x{:x}".format(function.getEntryPoint().getOffset()),
            "function": function
        })

    return functions

if __name__ == "__main__":

    program = r"<EXECUTABLE PATH HERE>"
    assert isfile(program), f"Invalid file: '{program}'"

    with pyhidra.open_program(program) as flat_api:
        
        # Extract the main (it is called by "entry")
        functions = get_functions(flat_api=flat_api, parent="entry")
        assert len(functions) == 1, "Unable to locate main"
        main = functions[0]
    
        print(f"Main function: {main['name']} at {main['address']}")

        # Extract all the handler function used in the main
        functions = get_functions(flat_api=flat_api, parent=main["name"])
        assert len(functions) == 1, "Unable to locate handler function"
        handler = functions[0]

        print(f"Handler function: {handler['name']} at {handler['address']}")
        
        # Get current program
        current_program = flat_api.getCurrentProgram()

        # Get all symbols that starts with DAT_
        symbols = [symbol for symbol in flat_api.currentProgram.getSymbolTable().getAllSymbols(True) if symbol.name.startswith("DAT_")]

        # Filter symbols: keep the ones that has at least one ref inside the handler function
        tmp = []

        for symbol in symbols:
            skip = False

            for ref in symbol.getReferences():
                ref_from_address = ref.getFromAddress()

                for block in handler["function"].getBody():
                    min_address = block.getMinAddress()
                    max_address = block.getMaxAddress()

                    if min_address <= ref_from_address and ref_from_address <= max_address:
                        tmp.append(symbol)
                        skip = True
                        break
                
                if skip:
                    break
        
        symbols = tmp[::-1]

        flag_ref = "UniTN"
        flag = ""

        # Analyze the content for each symbol
        for symbol in symbols:

            flag = ""

            address = symbol.getAddress()
            datatype_length = current_program.getListing().getDataAt(address).getDataType().getLength()

            while True:

                # Get data at the specified address
                value = current_program.getListing().getDataAt(address)

                # Try to extract it
                try:
                    value = value.getValue().getValue()
                except:
                    break
                
                # XOR the extracted value with 0x42
                value = chr(value ^ 0x42)

                # Check if it could be the flag or not
                flag = flag + value

                if not flag.startswith(flag_ref[:len(flag)]):
                    break

                if value == "}":
                    break
                
                # Increment the current position
                address = address.add(datatype_length)

            if len(flag) and flag_ref in flag:
                break
        
        print(flag)


