import argparse
from os import name
from typing import IO
import helpers
from pathlib import Path
from db import Base, create_db, Program, Function, Block, Instruction
from sqlalchemy.orm import sessionmaker

def main() -> None:
    # Data Collections
    FUNC = helpers.FUNCTION_COLLECTION
    PROG = helpers.PROGRAM_COLLECTION
    BLOCK = helpers.BLOCK_COLLECTION
    INST = helpers.INSTRUCTION_COLLECTION

    # CLI Arguments
    prs = argparse.ArgumentParser()
    prs.add_argument("file", help="parses the output of objdump -dwj .text {file}")
    args = prs.parse_args()
    # End CLI Arguments

    engine = create_db("test")
    SESSION = sessionmaker(bind=engine)
    session = SESSION()

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
        block_count = 1
        block_instructions = 0
        block_name = ""
        for i in inf:
            function = helpers._is_func(i)
            if function:
                    header = True
                    func_instructions = 0
                    func_name = (function.group(0).translate(str.maketrans({"<": "", ">": "", ":": ""})))       
            elif header:
                block_name = f"{func_name}_block_{block_count}"
                #Checks to see if we are still inside the function
                if i[0] == " ":
                    # accumulate instructions for function level count
                    
                    if helpers._is_jump(i):
                        jump_instructions+=1
                        block_instructions+=1
                        block = BLOCK(name=block_name,
                                      function=func_name,
                                      instruction_count=block_instructions)
                        BLOCKS.append(block)
                        block_count = block_count+1
                        block_instructions = 0
                    else:
                        block_instructions+=1
                    func_instructions+=1
                    # accumulate instructions
                    # Parse line with \t delimiter
                    split = i.split("\t")
                    if len(split) > 2:
                        el = split[2].split()
                        #print(el)
                        if len(el) > 1:
                            op = " ".join(el).replace("\n", "")
                        else:
                            op = None
                        inst = INST(block=block_name,
                                    name=el[0],
                                    offset=split[0].strip().replace(":", ""),
                                    bytes=split[1].strip(),
                                    op=op)
                        INSTRUCTIONS.append(inst)
                    # To catch a null byte
                    else:
                        inst = INST(block=block_name,
                                    name="NULL BYTE",
                                    offset=split[0].strip().replace(":", ""),
                                    bytes=split[1].strip(),
                                    op=None)
                        INSTRUCTIONS.append(inst)

                # Checks for newline that separates functions in objdump
                elif len(i) <= 1: 
                    
                    block = BLOCK(name=block_name,
                                      function=func_name,
                                      instruction_count=block_instructions)
                    BLOCKS.append(block)
                    
                    f = FUNC(name=func_name,
                             program=prog.name, 
                             instruction_count=func_instructions, 
                             jump_count=jump_instructions,
                             blocks=block_count)

                    # Add function to function collection
                    FUNCTIONS.append(f)
                    # Reset global variables
                    header = False
                    func_instructions = 0
                    jump_instructions = 0
                    block_count = 1
                    block_instructions = 0

        print(f"Analysis of {prog.name}\n\tSize Bytes:\t{prog.size}\n\tEntropy:\t{prog.entropy}")
        print(f"\nFunctions:\n")      
        for f in FUNCTIONS:
            print(f"Name: {f.name}\n\tInstructions: {f.instruction_count}\n\tJumps: {f.jump_count}\n\tBlocks: {f.blocks}")
            for i in INSTRUCTIONS:
                print(f"\n\t\tName: {i.name}\n\t\tBlock: {i.block}\n\t\tOffset: {i.offset}\n\t\tBytes: {i.bytes}\n\t\tOperation: {i.op}")
        for b in BLOCKS:
            print(f"Block:\n\t\tName: {b.name}\n\t\tMember: {b.function}\n\t\tInstructions: {b.instruction_count}")

        #print(prog.name)
        program = (Program(name=prog.name, 
                           block_setting=prog.block_setting,
                           average_blocks=prog.average_blocks,
                           entropy=prog.entropy,
                           raw_hex=prog.raw_hex,
                           size=prog.size))
        session.add(program)
        session.commit()

        for f in FUNCTIONS:
            f = (Function(name=f.name,
                program_id=program.id,
                instruction_count=f.instruction_count,
                jump_count=f.jump_count,
                blocks=f.blocks,
                average_block_size=f.instruction_count / f.blocks))

            session.add(f)
            session.commit()
            for b in BLOCKS:
                if b.function == f.name:
                    b = (Block(name=b.name,
                            function_id=f.id,
                            instruction_count=b.instruction_count))
                    session.add(b)
                    session.commit()
                    for i in INSTRUCTIONS:
                        if i.block == b.name:
                            i = (Instruction(name=i.name,
                                             block_id=b.id,
                                             offset=i.offset,
                                             byte_str=i.bytes,
                                             op=i.op))
                            session.add(i)
                            session.commit()

if __name__ == "__main__":
    main()
