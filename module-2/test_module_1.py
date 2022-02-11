import sys
import pathlib
import shutil

#from disasm_example import disassemble, getfile
from disasm3 import disassemble, getfile





def test_example1():
    sys.stdout.flush()

    direc = str(pathlib.Path(__file__).parent.resolve())
    in_path = direc + '\\data\\example1.o'
    out_path = direc + '\\data\\example1_test_out.txt'

    # open input object file
    in_bytes = getfile(in_path)

    # open output file
    sys.stdout = open(out_path, 'w')
    disassemble(in_bytes)
    sys.stdout.close()

    assert True

def test_example2():
    sys.stdout.flush()

    direc = str(pathlib.Path(__file__).parent.resolve())
    in_path = direc + '\\data\\example2.o'
    out_path = direc + '\\data\\example2_test_out.txt'

    # open input object file
    in_bytes = getfile(in_path)

    # open output file
    sys.stdout = open(out_path, 'w')
    disassemble(in_bytes)
    sys.stdout.close()

    assert True

def test_large():
    sys.stdout.flush()

    direc = str(pathlib.Path(__file__).parent.resolve())



    in_path = direc + '\\data\\large_example.o'
    out_path = direc + '\\data\\large_example_test_out'
    out_ext = ".txt"

    shutil.copyfile(out_path + out_ext, out_path + "_old" + out_ext)

    # open input object file
    in_bytes = getfile(in_path)

    # open output file
    sys.stdout = open(out_path + out_ext, 'w')
    disassemble(in_bytes)
    sys.stdout.close()

    assert True
