import collections
import re
from typing import IO
import os
import subprocess
from typing import Pattern
import pandas as pd 
from scipy.stats import entropy 




###################
# Begin Blacklist #
###################

BLACKLIST = [
    re.compile("<_.*"),
    re.compile("deregister_tm_clones"),
    re.compile("register_tm_clones"),
    re.compile("frame_dummy")

]

#################
# End Blacklist #
#################

#########################
# Begin Data Structures #
#########################

PROGRAM_COLLECTION = collections.namedtuple("Program", 
                                            "name \
                                             block_setting \
                                             average_blocks \
                                             entropy \
                                             raw_hex \
                                             size")

FUNCTION_COLLECTION = collections.namedtuple("Function",
                                             "program \
                                             name \
                                             instruction_count \
                                             jump_count \
                                             blocks" 
                                            )

BLOCK_COLLECTION = collections.namedtuple("Block",
                                          "name \
                                          function \
                                          instruction_count"
                                          )

INSTRUCTION_COLLECTION = collections.namedtuple("Instruction",
                                                "block \
                                                name \
                                                offset \
                                                bytes \
                                                op"
                                                )                                           
#######################
# End Data Structures #
#######################                                             

#########################
# Begin private methods #
#    accessed by the    # 
#    __main__ method    #
#########################
def _is_func(line: str, match: Pattern=r"<.*>:") -> bool:
    """ 
    Checks if the parameter line is a function header. Default value is r"<.*>:"
    If this is a function header this switches the header flag to True in the main method.
    :param line: A string which is a line of text read from the in file.
    :rtype: boolean
    :returns: If line matches function header
    """
    #match = r"<.*>:"
    if not any(re.search(b, line) for b in BLACKLIST):
        return re.search(match, line)

def _is_jump(line: str, match: Pattern=r"\tj[a-z]{1,4} ") -> bool:
    """ 
    Checks if the parameter line is a jump instruction. Default value is r"\tj[a-z]{1,4} ".
    :param line: A string which is a line of text read from the in file.
    :rtype: boolean
    :returns: If parameter line is a jump instruction based on the JUMP_PATTERN
    """
    #match = r"\tj[a-z]{1,4} "
    return re.search(match, line)

def _check_newline(inf: IO) -> None:
    """ 
    Checks if the paramater inf contains only a newline (\n) at the end of the file.
    if that is not the case this functions appends a \n to the end of the file
    :param inf: The file to be analyzed
    :rtype: None
    :returns: Nothing
    """
    with open(inf, "r+") as inf:
        if len(inf.readlines()[-1]) > 1:
            inf.write("\n")

#######################            
# End Private methods #
#######################

def get_size(inf: IO) -> str:
    """ 
    returns the size of the .TEXT section of a binary file.
    :param inf: The binary file to be analyzed
    :param outdir: The output directory of the processed file defaults to ./processed_files
    :rtype: str
    :returns: The size of the .TEXT section as a decimal number.
    """
    return subprocess.getoutput("size " + inf + " | awk \'{print $1}\' | tail -1") 

def disassemble_binary(inf: IO, outdir: str="./processed_files") -> str:
    """ 
    Creates a disassembled .TEXT section binary file (inf) in  outdir called {outdir}/{inf}.dis.
    :param inf: The binary file to dumped in the format of objdump -dj .text {inf}
    :param outf: the destination of the dump file. Defaults to ./processed_files/{inf}.dis
    :rtype: str
    :returns: The name of the dump file.
    """
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    dest = f"{outdir}/{os.path.basename(inf)}.dis"
    subprocess.getoutput(f"objdump -dwj .text {inf} > {dest}")
    return dest

def make_raw_hex(inf: IO, outdir: str="./processed_files") -> str:
    """ 
    Creates a raw aw binary dump (outdir/{inf}.dump) and a hexidecimal representation (outdir/{inf}.hex) 
    of the .TEXT section of the binary file (inf) in  outdir. 
    :param inf: The binary file to dumped in the format of objdump -dj .text {inf}
    :param outf: the destination of the dump file. Defaults to ./processed_files/{inf}{.dump | .hex}
    :rtype: str
    :returns: The name of the hex file.
    """
    # get raw hex from .text
    # https://unix.stackexchange.com/a/421558
    # objcopy -O binary -j .text a.out a.dump ; od -An -t x1 a.dump > a.hex
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    dest = f"{outdir}/{os.path.basename(inf)}"
    f = f"{dest}.hex"
    subprocess.getoutput(f"objcopy -O binary -j .text {inf} {dest}.dump ; \
                          od -An -t x1 {dest}.dump > {dest}.hex")
    return f

def calculate_entropy(inf: IO) -> float:
    """ 
    Calculates the entropy of the parameter inf (approximates Shannon's entropy).
    :param inf: A file with the raw hexidecimal values to be analyzed.
    :rtype: float
    :returns: The calculated entropy of the file.
    """
    # Shannon entropy a.hex: 3.319071417214196 https://gchq.github.io/CyberChef
    # https://www.kite.com/python/answers/how-to-calculate-shannon-entropy-in-python
    # https://onestopdataanalysis.com/shannon-entropy/
    dump = open(inf, "r").read().replace("\n", "").replace(" ", "")
    #print(f"Raw Hex:\n\n{dump}\n")
    #byteme = [int(dump[i:i+2], 16) for i in range(0, len(dump), 2)]
    byteme = [dump[i:i+2] for i in range(0, len(dump), 2)]
    series = pd.Series(byteme)
    return entropy(series.value_counts())
    # return entropy([x/sum(series.value_counts()) for x in series.value_counts()])