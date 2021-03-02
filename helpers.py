import re
from types import BuiltinMethodType
from typing import IO
import os
import subprocess
from typing import Pattern
import pandas as pd #TODO add to requirements.txt
from scipy.stats import entropy #TODO add to requirements.txt



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
    :returns: The size of the .TEXT section as a decimal number and creates a new file in 
              outdir called {outdir}/{inf}.dump
    """
    return subprocess.getoutput("size " + inf + " | awk \'{print $1}\' | tail -1") 

def dump_binary(inf: IO, outdir: str="./processed_files") -> str:
    """ 
    Creates a dump of the .TEST section binary file (inf).
    :param inf: The binary file to dumped in the format of objdump -dj .text {inf}
    :param outf: the destination of the dump file. Defaults to ./test_files/tmp.txt
    :rtype: str
    :returns: The name of the dump file
    """
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    dest=f"{outdir}/{os.path.basename(inf)}.dump"
    subprocess.getoutput(f"objdump -dj .text {inf} > {dest}")
    return dest

def calculate_entropy(inf: IO):
    dump = subprocess.getoutput(f"xxd -ps {inf}").replace("\n", "")
    #byteme = [dump[i:i+2] for i in range(0, len(dump), 2)]
    byteme = [int(dump[i:i+2], 16) for i in range(0, len(dump), 2)]
    return entropy(byteme, base=256) #base=255 or 16?
    #return byteme