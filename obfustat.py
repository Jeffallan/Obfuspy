import argparse
from typing import IO
import helpers


def main() -> None:
    # Data Collections
    FUNC = helpers.FUNCTION_COLLECTION
    PROG = helpers.PROGRAM_COLLECTION
    CMD = helpers.INSTRUCTION_COLLECTION
    # CLI Arguments
    prs = argparse.ArgumentParser()
    prs.add_argument("file", help="parses the output of objdump -dj .text {file}")
    args = prs.parse_args()
    # End CLI Arguments

    #TODO add flag for custom function and jump matching REGEX.
    size = helpers.get_size(args.file)
    disassemble = helpers.disassemble_binary(args.file)
    hexdump = helpers.make_raw_hex(args.file)
    #report size
    print(f"Size of .TEXT {size}\n")
    print(f"Entropy: {helpers.calculate_entropy(hexdump)}\n")
    FUNCTIONS = []
    helpers._check_newline(disassemble)
    with open(disassemble) as inf:
        header = False
        n = ""
        instructions = 0
        jump_instructions = 0
        for i in inf:
            function = helpers._is_func(i)
            if function:
                    header = True
                    instructions = 0
                    n = (function.group(0).translate(str.maketrans({"<": "", ">": "", ":": ""})))
            elif header:
                if i[0] == " ": 
                    instructions+=1
                    if helpers._is_jump(i):
                        jump_instructions+=1
                elif len(i) <= 1: 
                    f = FUNC(name=n, 
                             instruction_count=instructions, 
                             jump_count=jump_instructions,
                             blocks=0)

                    FUNCTIONS.append(f)
                    header = False
                    instructions = 0
                    jump_instructions = 0      
        for f in FUNCTIONS:
            print(f"Name: {f.name}\n\tInstructions: {f.instruction_count}\n\tJumps: {f.jump_count}")
if __name__ == "__main__":
    main()
