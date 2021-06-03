import argparse
from os import name
from typing import IO
import helpers
from pathlib import Path
from db import Base, create_db, Program, Function, Block, Instruction
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from csv import DictWriter


def main() -> None:
    # Data Collections
    FUNC = helpers.FUNCTION_COLLECTION
    PROG = helpers.PROGRAM_COLLECTION
    BLOCK = helpers.BLOCK_COLLECTION
    INST = helpers.INSTRUCTION_COLLECTION

    # CLI Arguments
    prs = argparse.ArgumentParser()
    prs.add_argument(
        "file", help="Parses the output of objdump -dwj .text {file}")
    prs.add_argument(
        "--llvm_blocks", help="The number of LLVM blocks", default=0)
    prs.add_argument("--llvm_instructions",
                     help="The number of LLVM instructions", default=0)
    prs.add_argument("--average_instructions",
                     help="The average number of LLVM instructions per block", default=0)
    args = prs.parse_args()
    # End CLI Arguments
    """
    engine = create_db(f"{args.file.split('/')[-1]}")
    SESSION = sessionmaker(bind=engine)
    session = SESSION()
    """
    size = helpers.get_size(args.file)
    disassemble = helpers.disassemble_binary(args.file)
    hexdump = helpers.make_raw_hex(args.file)
    
    prog = PROG(name=Path(args.file).name,
                llvm_blocks=args.llvm_blocks,
                llvm_instructions=args.llvm_instructions,
                average_instructions=args.average_instructions,
                entropy=helpers.calculate_entropy(hexdump),
                raw_hex=hexdump,
                size=size)
    """
    program = (Program(name=prog.name,
                       llvm_blocks=prog.llvm_blocks,
                       llvm_instructions=prog.llvm_instructions,
                       average_instructions=prog.average_instructions,
                       entropy=prog.entropy,
                       raw_hex=prog.raw_hex,
                       size=prog.size))
    session.add(program)
    session.commit()
    """
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
        block_count = 0
        block_instructions = 0
        block_name = ""
        for i in inf:
            function = helpers._is_func(i)
            if function:
                header = True
                func_instructions = 0
                func_name = (function.group(0).translate(
                    str.maketrans({"<": "", ">": "", ":": ""})))
                """
                func_1 = (Function(name=func_name,
                                   program_id=program.id,
                                   instruction_count=0,
                                   jump_count=0,
                                   blocks=0,
                                   average_block_size=0))
                session.add(func_1)
                session.commit()
                """
                if block_count == 0:
                    block_name = f"{func_name}_block_{block_count}"
                    """
                    blk_1 = (Block(name=block_name,
                                           function_id=func_1.id,
                                           instruction_count=0))
                    session.add(blk_1)
                    session.commit()
                    """
            elif header:
                block_name = f"{func_name}_block_{block_count}"
                # Checks to see if we are still inside the function
                if i[0] == " ":
                    # accumulate instructions for function level count
                    if helpers._is_jump(i):
                        jump_instructions += 1
                        block_instructions += 1
                        block = BLOCK(name=block_name,
                                      function=func_name,
                                      instruction_count=block_instructions)
                        BLOCKS.append(block)
                        """
                        b = session.query(Block).get(blk_1.id)
                        b.instruction_count=block.instruction_count
                        session.commit()
                        blk_1 = (Block(name=block.name,
                                       function_id=func_1.id,
                                       instruction_count=block.instruction_count))
                        session.add(blk_1)
                        session.commit()
                        """
                        block_count = block_count+1
                        block_instructions = 0
                    else:
                        block_instructions += 1
                    func_instructions += 1
                    # accumulate instructions
                    # Parse line with \t delimiter
                    split = i.split("\t")
                    if len(split) > 2:
                        el = split[2].split()
                        # print(el)
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
                        """
                        i = (Instruction(name=inst.name,
                                             block_id=blk_1.id,
                                             offset=inst.offset,
                                             byte_str=inst.bytes,
                                             op=inst.op))
                        session.add(i)
                        session.commit()
                        """
                    # To catch a null byte
                    else:
                        inst = INST(block=block_name,
                                    name="NULL BYTE",
                                    offset=split[0].strip().replace(":", ""),
                                    bytes=split[1].strip(),
                                    op=None)
                        INSTRUCTIONS.append(inst)
                        """
                        i = (Instruction(name=inst.name,
                                             block_id=blk_1.id,
                                             offset=inst.offset,
                                             byte_str=inst.bytes,
                                             op=inst.op))
                        session.add(i)
                        session.commit()
                        """
                # Checks for newline that separates functions in objdump
                elif len(i) <= 1:

                    block = BLOCK(name=block_name,
                                  function=func_name,
                                  instruction_count=block_instructions)
                    if block.instruction_count > 0:
                        BLOCKS.append(block)
                        """
                        blk_2 = session.query(Block).get(blk_1.id)
                        blk_2.instruction_count = block.instruction_count
                        session.commit()
                        """
                    # Add function to function collection
                    f = FUNC(name=func_name,
                             program=prog.name,
                             instruction_count=func_instructions,
                             jump_count=jump_instructions,
                             blocks=block_count)

                    FUNCTIONS.append(f)
                    """
                    func_2 = session.query(Function).get(func_1.id)
                    func_2.instruction_count = f.instruction_count
                    func_2.jump_count = f.jump_count
                    func_2.blocks = f.blocks
                    func_2.average_block_size = f.instruction_count / f.blocks
                    session.commit()
                    """

                    # Reset global variables
                    header = False
                    func_instructions = 0
                    jump_instructions = 0
                    block_count = 1
                    block_instructions = 0

        out_dict = {"program": prog.name,
                    "size": prog.size,
                    "total_functions": len([f.name for f in FUNCTIONS]),
                    "total_instructions": sum(f.instruction_count for f in FUNCTIONS),
                    "total_jumps": sum(f.jump_count for f in FUNCTIONS),
                    "total_blocks": sum(f.jump_count for f in FUNCTIONS)}

        nl = "\n"
        print(f'{nl.join(f"{k}: {v}" for k, v in out_dict.items())}')
        print("\n")
        #print(f"\nFunctions:\n")

        p = Path("./results")
        if p.exists() == False:
            p.mkdir(parents=True, exist_ok=True)
        #make csv
        if Path(p / "results.csv").exists() == False:
            with open(f"./results/results.csv", "a") as csv:
                writer = DictWriter(csv, fieldnames=list(out_dict.keys()))
                writer.writeheader()
                writer.writerow(out_dict)
        with open(f"./results/results.csv", "a") as csv:
            writer = DictWriter(csv, fieldnames=list(out_dict.keys()))
            #writer.writeheader()
            writer.writerow(out_dict)
        # make logfile
        with open(f"./results/results.log", "a") as lf:
            lf.write(f"Program: {prog.name}\n")
            for f in FUNCTIONS:
                lf.write(
                    f"\tName: {f.name}\n\t\tInstructions: {f.instruction_count}\n\t\tJumps: {f.jump_count}\n\t\tBlocks: {f.blocks}")
                lf.write("\n\n")
if __name__ == "__main__":
    main()
