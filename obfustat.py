import re
import collections
import argparse
from typing import IO
import os
import subprocess
import helpers


def main() -> None:
    # a collection object to hold data about the identified functions
    FUNC = collections.namedtuple("Function", "name instruction_count jump_count")
    prs = argparse.ArgumentParser()
    prs.add_argument("file", help="parses the output of objdump -dj .text {file}")
    args = prs.parse_args()
    #TODO add flag for custom function and jump matching REGEX.
    size = helpers.get_size(args.file)
    dump = helpers.dump_binary(args.file)
    #report size
    print(f"Size of .TEXT {size}\n")
    #TODO report Shannon's entropy
    #print(f"Entropy: {helpers.calculate_entropy(dump)}")
    FUNCTIONS = []
    helpers._check_newline(dump)
    with open(dump) as inf:
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
                             jump_count=jump_instructions)

                    FUNCTIONS.append(f)
                    header = False
                    instructions = 0
                    jump_instructions = 0      
        for f in FUNCTIONS:
            print(f"Name: {f.name}\n\tInstructions: {f.instruction_count}\n\tJumps: {f.jump_count}")
if __name__ == "__main__":
    main()
