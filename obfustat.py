import argparse
from typing import IO
import helpers
from pathlib import Path


def main() -> None:
    # Data Collections
    FUNC = helpers.FUNCTION_COLLECTION
    PROG = helpers.PROGRAM_COLLECTION
    BLOCK = helpers.BLOCK_COLLECTION
    INST = helpers.INSTRUCTION_COLLECTION

    # CLI Arguments
    prs = argparse.ArgumentParser()
    prs.add_argument("file", help="parses the output of objdump -dj .text {file}")
    args = prs.parse_args()
    # End CLI Arguments

    size = helpers.get_size(args.file)
    disassemble = helpers.disassemble_binary(args.file)
    hexdump = helpers.make_raw_hex(args.file)

    prog = PROG(name=Path(args.file).name,
                block_setting=0, # TODO get this info from parsing Bill's file names
                average_blocks=0, # TODO get this info from parsing Bill's file names
                entropy=helpers.calculate_entropy(hexdump),
                raw_hex=hexdump,
                size=size)

    # Lists for storing information about the functions, blocks, and instructions 
    FUNCTIONS = []          
    INSTRUCTIONS = []
    BLOCKS = []

    helpers._check_newline(disassemble)
    with open(disassemble) as inf:
        header = False
        func_name = ""
        func_instructions = 0
        jump_instructions = 0
        block_instructions = 0 
        for i in inf:
            function = helpers._is_func(i)
            if function:
                    header = True
                    func_instructions = 0
                    func_name = (function.group(0).translate(str.maketrans({"<": "", ">": "", ":": ""})))
            elif header:
                #Checks to see if we are still inside the function
                if i[0] == " ":
                    # accumulate instructions for function level count
                    func_instructions+=1
                    if helpers._is_jump(i):
                        jump_instructions+=1
                    
                    # accumulate instructions
                    # Parse line with \t delimiter
                    split = i.split("\t")
                    if len(split) > 2:
                        el = split[2].split()
                        print(el)
                        if len(el) > 1:
                            op = " ".join(el).replace("\n", "")
                        else:
                            op = None
                        inst = INST(block="CHANGEME",
                                    name=el[0],
                                    offset=split[0].strip().replace(":", ""),
                                    bytes=split[1].strip(),
                                    op=op)
                        INSTRUCTIONS.append(inst)
                    # To catch a null byte
                    else:
                        inst = INST(block="CHANGEME",
                                    name="NULL BYTE",
                                    offset=split[0].strip().replace(":", ""),
                                    bytes=split[1].strip(),
                                    op=None)
                        INSTRUCTIONS.append(inst)

                # Checks for newline that separates functions in objdump
                elif len(i) <= 1: 
                    f = FUNC(name=func_name,
                             program=prog.name, 
                             instruction_count=func_instructions, 
                             jump_count=jump_instructions,
                             blocks=0)

                    # Add function to function collection
                    FUNCTIONS.append(f)
                    header = False
                    func_instructions = 0
                    jump_instructions = 0

        print(f"Analysis of {prog.name}\n\tSize Bytes:\t{prog.size}\n\tEntropy:\t{prog.entropy}")
        print(f"\nFunctions:\n")      
        for f in FUNCTIONS:
            print(f"Name: {f.name}\n\tInstructions: {f.instruction_count}\n\tJumps: {f.jump_count}")
            for i in INSTRUCTIONS:
                print(f"\n\t\tName: {i.name}\n\t\tOffset: {i.offset}\n\t\tBytes: {i.bytes}\n\t\tOperation: {i.op}")

if __name__ == "__main__":
    main()
