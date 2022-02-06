import sys
from disasm_example import disassemble, getfile
import pathlib

from disasm import disassemble as dis2



def test_example1():
    sys.stdout.flush()

    direc = str(pathlib.Path(__file__).parent.resolve())
    in_path = direc + '\\data\\example1.o'
    out_path = direc + '\\data\\example1_test_out.txt'

    # open input object file
    in_bytes = getfile(in_path)

    # open output file
    sys.stdout = open(out_path, 'w')
    dis2(in_bytes)
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
    dis2(in_bytes)
    sys.stdout.close()

    assert True

def test_large():
    sys.stdout.flush()

    direc = str(pathlib.Path(__file__).parent.resolve())
    in_path = direc + '\\data\\large_example.o'
    out_path = direc + '\\data\\large_example_test_out.txt'

    # open input object file
    in_bytes = getfile(in_path)

    # open output file
    sys.stdout = open(out_path, 'w')
    dis2(in_bytes)
    sys.stdout.close()

    assert True