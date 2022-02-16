from gettext import find
from pickle import FALSE
from re import L
import sys
from enum import Enum
import queue
from typing import Tuple
import argparse
import os.path

# 32 bit architecture
DEF_OP_SIZE = 4

# operand types to process differently
class OpTypes(Enum):
    Reg = 0
    RM = 1
    Included = 2
    Immediate = 4
    RD = 5

# class that holds information about the operands
class OpInfo() :
    
    def __init__(self, base_op : int, instr_str : str, req_rm : bool, encoding : str, op_types_arr : OpTypes, ext : str, imm_len : int):
        self.base_op = base_op
        self.instr = instr_str
        self.req_rm = req_rm
        self.encoding = encoding
        self.op_types = op_types_arr
        self.ext = ext
        self.imm_len = imm_len

# holds a parsed instruction
class Instruction() :
    
    def __init__(self, prefix, op, mod, reg, rm, scale, index, base, disp, rm_disp_len, imm, orig_addr, total_len, has_sib):
        self.prefix = prefix
        self.op = op
        self.mod = mod
        self.reg = reg
        self.rm = rm
        self.scale = scale
        self.index = index
        self.base = base
        self.disp = disp
        self.rm_disp_len = rm_disp_len
        self.imm = imm
        self.orig_addr = orig_addr
        self.total_len = total_len
        self.has_sib = has_sib

ONEB_GLOBAL_OPCODE_LIST = {

}

def add_opinfo_to_list(list, op_code, op_info):
    if op_code in list:
        exist = list[op_code]
        exist.append(op_info)
        list[op_code] = exist
    else:
        list[op_code] = [op_info]

def add_op_to_list(list, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len):
    op_info = OpInfo(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len)
    if op_code in list:
        list[op_code].append(op_info)
    else:
        list[op_code] = [op_info]

def add_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm):
    add_op_to_list(ONEB_GLOBAL_OPCODE_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm)

add_op(0x01, "add", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x03, "add", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
add_op(0x05, "add eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0x25, "and eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0x81, "and", True, "mi", [OpTypes.RM, OpTypes.Immediate], "4", DEF_OP_SIZE)
add_op(0x21, "and", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x23, "and", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", DEF_OP_SIZE)
add_op(0x39, "cmp", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x81, "add", True, "mi", [OpTypes.RM, OpTypes.Immediate], "0", DEF_OP_SIZE)
add_op(0x89, "mov", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x8b, "mov", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
add_op(0x3D, "cmp", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0x81, "cmp", True, "mi", [OpTypes.RM, OpTypes.Immediate], "7", DEF_OP_SIZE)
add_op(0x3B, "cmp", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
add_op(0xFF, "dec", True, "m", [OpTypes.RM], "1", 0)
add_op(0xF7, "idiv", True, "m", [OpTypes.RM], "7", 0)
add_op(0xFF, "inc", True, "m", [OpTypes.RM], "0", 0)
add_op(0x8D, "lea", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
add_op(0xC7, "mov", True, "mi", [OpTypes.RM, OpTypes.Immediate], "0", DEF_OP_SIZE)
add_op(0xA5, "movsd", False, "zo", [], "", 0)
add_op(0x90, "nop", False, "zo", [], "", 0)
add_op(0xF7, "not", True, "m", [OpTypes.RM], "2",0)
add_op(0x0D, "or eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0x81, "or", True, "mi", [OpTypes.RM, OpTypes.Immediate], "1", DEF_OP_SIZE)
add_op(0x09, "or", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x0B, "or", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
add_op(0x8F, "pop", True, "m", [OpTypes.RM], "0", 0)
add_op(0xFF, "push", True, "m", [OpTypes.RM], "6", 0)
add_op(0x68, "push", False, "i", [OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0xA7, "cmpsd", False, "zo", [], "", 0)
add_op(0xCB, "retf", False, "zo", [], "", 0)
add_op(0xCA, "retf", False, "i", [OpTypes.Immediate], "", 2)
add_op(0xC2, "retn", False, "i", [OpTypes.Immediate], "", 2)
add_op(0xC3, "retn", False, "zo", [], "", 0)
add_op(0x2D, "sub eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0x81, "sub", True, "mi", [OpTypes.RM, OpTypes.Immediate], "5", DEF_OP_SIZE)
add_op(0x29, "sub", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x2B, "sub", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
add_op(0xA9, "test eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0xF7, "test", True, "mi", [OpTypes.RM, OpTypes.Immediate], "0", DEF_OP_SIZE)
add_op(0x85, "test", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x35, "xor eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
add_op(0x81, "xor", True, "mi", [OpTypes.RM, OpTypes.Immediate], "6", DEF_OP_SIZE)
add_op(0x31, "xor", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
add_op(0x33, "xor", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)

TWOB_GLOBAL_OPCODE_LIST = {
    
}

def add_twob_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len):
    add_op_to_list(TWOB_GLOBAL_OPCODE_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len)

add_twob_op(0xAE, "clflush", False, "m", [OpTypes.RM], "0", 0)

THREEB_GLOBAL_OPCODE_LIST = {

}

JUMP_INSTR_LIST = {

}

def add_jmp_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len):
    add_op_to_list(JUMP_INSTR_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len)
    add_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len)

add_jmp_op(0xEB, "jmp", False, "d", [OpTypes.Immediate], "", 1)
add_jmp_op(0xE9, "jmp", False, "d", [OpTypes.Immediate], "", DEF_OP_SIZE)
add_jmp_op(0xFF, "jmp", True, "m", [OpTypes.RM], "4", 0)
add_jmp_op(0x74, "jz", False, "d", [OpTypes.Immediate], "", 1)
add_jmp_op(0x75, "jz", False, "d", [OpTypes.Immediate], "", 1)
add_jmp_op(0xE8, "call", False, "d", [OpTypes.Immediate], "", DEF_OP_SIZE)
add_jmp_op(0xFF, "call", False, "d", [OpTypes.Immediate], "3", DEF_OP_SIZE)

TWOB_JUMP_INSTR_LIST = {

}

def add_twob_jump(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len):
    add_op_to_list(TWOB_JUMP_INSTR_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len)

add_twob_jump(0x84, "jnz", False, "d", [OpTypes.Immediate], "", 4)
add_twob_jump(0x85, "jz", False, "d", [OpTypes.Immediate], "",  4)

MAX_OPCODE_BYTES = 3
TWO_BYTE_OPCODE = 0xF
THREE_BYTE_OPCODE_1 = 0x38
THREE_BYTE_OPCODE_2 = 0x39

class PREFIX_LIST_INDEX_ENUM(Enum) :
    PREFIX = 0

PREFIX_LIST = {
    0xF2 : ["repne"]
}

class GLOBAL_REGISTER_NAMES(Enum) : 
    eax = 0
    ecx = 1
    edx = 2
    ebx = 3
    esp = 4
    ebp = 5
    esi = 6
    edi = 7

# Build opcodes that use opcode + rd
OP_EN_O_OPS = {
    0x50 : ["push", "o", [OpTypes.RD], "", 0],
    0x58 : ["pop", "o", [OpTypes.RD], "", 0],
    0xB8 : ["mov", "oi", [OpTypes.RD, OpTypes.Immediate], "", DEF_OP_SIZE],
    0x48 : ["dec", "i", [OpTypes.RD], "1", 0],
    0x40 : ["inc", "o", [OpTypes.RD], "", 0]
}

def add_op_rd(op_code, base_op, instr_str, req_rm, encoding, op_types_arr, ext, imm_len):
    opinf = OpInfo(base_op, instr_str, req_rm, encoding, op_types_arr, ext, imm_len)
    add_opinfo_to_list(ONEB_GLOBAL_OPCODE_LIST, op_code, opinf)


for reg in GLOBAL_REGISTER_NAMES:
    for op_val in OP_EN_O_OPS:
        entry = OP_EN_O_OPS[op_val]
        add_op_rd(op_val + reg.value, op_val, entry[0], False, entry[1], entry[2], entry[3], entry[4])


# Sanity check for duplicate ops
for oplists_key in ONEB_GLOBAL_OPCODE_LIST:
    exts = set()
    oplist = ONEB_GLOBAL_OPCODE_LIST[oplists_key]
    for op in oplist:
        if op.ext in exts:
            print("Duplicate opcode found {:s} {:x}".format(op.instr, op.base_op))
        elif op.ext != "r":
            exts.add(op.ext)


BYTEODER = "little"

LABELS = {

}

REG_KEY = 0
RM_KEY = 1

def is_prefix(prefix):
    return prefix in PREFIX_LIST.keys()

def is_opcode(opcode):
    num_bytes = len(opcode)
    if num_bytes <= 0:
        return (False, 0)

    is_opcode = False
    opcode_num_bytes = 0

    b0 = opcode[0]
    if b0 == TWO_BYTE_OPCODE:
        # is 2 or more byte opcode
        
        if num_bytes > 1:
            b1 = opcode[1]

            if b1 == THREE_BYTE_OPCODE_1 or b1 == THREE_BYTE_OPCODE_2:
                #is a three byte or unknown opcode
                if num_bytes > 2:
                    b2 = opcode[2]
                    is_opcode = b2 in THREEB_GLOBAL_OPCODE_LIST.keys()
                    
                opcode_num_bytes = 3
            
            else:
                # is two byte or unknown opcode
                is_opcode = b1 in TWOB_GLOBAL_OPCODE_LIST.keys()
                opcode_num_bytes = 2            

        # else not enough bytes, not opcode
    else:
        # is single byte opcode
        is_opcode = b0 in ONEB_GLOBAL_OPCODE_LIST.keys()
        opcode_num_bytes = 1

    return (is_opcode, opcode_num_bytes)

def is_jump(opcode):
    return opcode in JUMP_INSTR_LIST or opcode in TWOB_JUMP_INSTR_LIST

def parseMODRM(modrm):
    mod = (modrm & 0xC0) >> 6
    reg = (modrm & 0x38) >> 3
    rm  = (modrm & 0x07)
    return (mod, reg, rm)

def parseSIB(sib):
    return parseMODRM(sib)

def format_byte(byte):
    return "0x{:02X}h".format(byte)

def format_word(word):
    return "0x{:04X}h".format(word)

def format_dword(dword):
    return "0x{:08X}h".format(dword)

def format_label(addr):
    return "offset_{:08X}h".format(addr)

def printDisasm( l ):

    # Good idea to add a "global label" structure...
    # can check to see if "addr" is in it for a branch reference

    label_count = 0

    for addr in sorted(l):
        int_addr = int(addr, 16)
        if int_addr in LABELS:
            print(LABELS[int_addr] + ":")
            label_count += 1

        print( "%s: %s" % (addr, l[addr]) )

def format_address(byte_idx):
    return "{:08X}".format(byte_idx)

def format_instr(instr_str):
    return "{:<18s}".format(instr_str)

def format_byte_str(bytes_str):
    return "{:<18s}".format(''.join('{:02X}'.format(x) for x in bytes_str))

def handle_prefix(byte):
    bytes_used = 1
    instruction_str = PREFIX_LIST[byte][PREFIX_LIST_INDEX_ENUM.PREFIX.value]
    return (bytes_used, instruction_str)

def handle_reg(opinfo : OpInfo, instr : Instruction) -> str:
    return GLOBAL_REGISTER_NAMES(instr.reg).name

def handle_rm(opinfo : OpInfo, instr : Instruction) -> str:
    #if instr.has_sib:
       # return handle_sibrm(opinfo, instr)
    
    if instr.mod == 3:
        #print ('r/m32 operand is direct register')
        return GLOBAL_REGISTER_NAMES(instr.rm).name

    elif instr.mod == 2:
        #print ('r/m32 operand is [ reg + disp32 ] -> please implement')
        return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + " + " + format_dword(instr.disp) + "]"

    elif instr.mod == 1:
        #print ('r/m32 operand is [ reg + disp8 ] -> please implement')
        # will need to parse the displacement8
        return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + " + " + format_byte(instr.disp) + "]"

    else:
        if instr.rm == 5:
            #print ('r/m32 operand is [disp32] -> please implement')
            return "[" + format_dword(instr.disp) + "]"

        elif instr.rm == 4:
            #print ('Indicates SIB byte required -> not required to implement')
            return handle_sibrm(opinfo, instr)
            
        else:# rm == 0-3
            return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + "]"
            #print ('r/m32 operand is [reg] -> please implement')
    

def handle_sibrm(opinfo : OpInfo, instr : Instruction) -> str:
    SIB_SPCL_CASE_BASE = 0b101
    SIB_SPCL_CASE_MOD = 0b00

    if instr.base == SIB_SPCL_CASE_BASE and instr.mod == SIB_SPCL_CASE_MOD:
        base_reg_str = ""# no base register
    else:
        base_reg_str = GLOBAL_REGISTER_NAMES(instr.base).name

    if instr.base == GLOBAL_REGISTER_NAMES.esp.value:
        # esp cannot be scaled
        index_scale = ""
    else:
        scale = pow(2, instr.scale)
        index_scale = GLOBAL_REGISTER_NAMES(instr.index).name + (" * " + str(scale) if scale > 1 else "")
        
    displacement = (" + " + format_dword(instr.disp)) if instr.disp != 0 else ""

    return "[" + index_scale + (" + " if index_scale != "" else "") + base_reg_str + displacement + "]"

def handle_included(opinfo : OpInfo, instr : Instruction) -> str:
    return ""

def handle_immediate(opinfo : OpInfo, instr : Instruction) -> str:
    if is_jump(opinfo.base_op):
        target = instr.orig_addr + instr.imm + instr.total_len
        LABELS[target] = format_label(target)
        return LABELS[target]
    else:
        return format_dword(instr.imm)

def handle_rd(opinfo : OpInfo, instr : Instruction) -> str:
    return GLOBAL_REGISTER_NAMES(instr.op - opinfo.base_op).name

def handle_displacement(opinfo : OpInfo, instr : Instruction) -> str:
    if is_jump(opinfo.base_op):
        target = instr.orig_addr + instr.disp + instr.total_len
        LABELS[target] = format_label(target)
    
    return LABELS[target]

OPERAND_HANDLERS = {
    OpTypes.Reg : handle_reg,
    OpTypes.RM : handle_rm,
    OpTypes.Included : handle_included,
    OpTypes.Immediate : handle_immediate,
    OpTypes.RD : handle_rd
}

def parse_instruction(opcode_info_list, bytes, orig_addr, prefix_bytes) -> Tuple[int, Instruction, OpInfo]:
    num_bytes = len(bytes)
    opcode_byte = bytes[0]
    bytes_used = 1

    prefix = 0
    mod = 0
    reg = 0
    rm = 0
    scale = 0
    index = 0
    base = 0
    disp = 0
    imm = 0

    poss_opcodes = len(opcode_info_list)
    if poss_opcodes > 1:
        if num_bytes >= 2:
            # opcode has a /ext and need to pick correct one
            # every /ext requires modrm
            (m, r, rm) = parseMODRM(bytes[1])
            reg_str = str(r)
            def condition(x : OpInfo): return x.ext == reg_str
            idx_of_op = [idx for idx, element in enumerate(opcode_info_list) if condition(element)]
            if len(idx_of_op) == 0:
                return (0, None, None)
            if len(idx_of_op) > 1:
                pass#This is an error, multiple ops with same ext
            else:
                opinfo = opcode_info_list[idx_of_op[0]]
        else:
            return (0, None, None)
    elif poss_opcodes == 1:
        opinfo = opcode_info_list[0]
    else:
        return (0, None, None)
    
    modrm_disp_bytes = 0
    has_sib = False

    # figure out operands
    if opinfo.req_rm:
        # has mod rm
        (mod, reg, rm) = parseMODRM(bytes[bytes_used])
        bytes_used += 1

        # check if modrm requires displacement
        if mod == 1:
            modrm_disp_bytes = 1
        elif mod == 2 or (mod == 0 and rm == 5):
            modrm_disp_bytes = 4
            
        # if it has modrm, it may have sib
        has_sib = rm == 4 and (mod == 0 or mod == 1 or mod == 2)
        if has_sib:
            (scale, index, base) = parseSIB(bytes[bytes_used])
            bytes_used += 1
            # exception
            if mod == 0 and rm == 4 and base == 4:
                #modrm_disp_bytes = 4
                pass

    op_types = opinfo.op_types
    num_ops = len(op_types)

    has_disp = modrm_disp_bytes > 0
    if has_disp:
        # parse displacement
        disp = int.from_bytes(bytes[bytes_used:bytes_used + modrm_disp_bytes], BYTEODER)
        bytes_used += modrm_disp_bytes

    has_imm = OpTypes.Immediate in op_types
    if has_imm:
        # parse immediate
        imm = int.from_bytes(bytes[bytes_used:bytes_used + opinfo.imm_len], BYTEODER)
        bytes_used += opinfo.imm_len

    instr = Instruction(prefix, opcode_byte, mod, reg, rm, scale, index, base, disp, modrm_disp_bytes, imm, orig_addr, bytes_used + prefix_bytes, has_sib)
    
    return (bytes_used, instr, opinfo)


def handle_opcode(opcode_info_lst : OpInfo, bytes, orig_addr, bytes_used):
    
    (instr_len, instruction, opinfo) = parse_instruction(opcode_info_lst, bytes, orig_addr, bytes_used)

    if instr_len <= 0:
        return (0, "")

    instr_str = opinfo.instr + " "

    num_operands = len(opinfo.op_types)

    for idx, op_type in enumerate(opinfo.op_types):
        if op_type in OPERAND_HANDLERS:

            if op_type == OpTypes.Included: instr_str = instr_str[:-1]#remove extra space

            instr_str += OPERAND_HANDLERS[op_type](opinfo, instruction)
            if idx < num_operands - 1:
                instr_str += ", "

    return (instr_len, instr_str)

def handle_twob_opcode(bytes, orig_addr, bytes_used):
    num_bytes = len(bytes)

    if num_bytes >= 2:
        opcode_info = TWOB_GLOBAL_OPCODE_LIST[bytes[1]]
        (bytes_used, instruction_str) = handle_opcode(opcode_info, bytes[1:num_bytes], orig_addr, bytes_used)
        return (bytes_used + 1, instruction_str)

    return (0, "", "")

def handle_threeb_opcode(bytes, orig_addr):
    num_bytes = len(bytes)

    if num_bytes >= 3:
        opcode_info = THREEB_GLOBAL_OPCODE_LIST[bytes[2]]
        (bytes_used, instruction_str) = handle_opcode(bytes[2:num_bytes], orig_addr)
        return (bytes_used + 2, instruction_str)

    return (0, "", "")

def format_unknown_instr_str(byte):
    return "db {:02X}".format(byte & 0xff)

def disasm_instruction(instr_bytes, orig_addr):
    total_bytes = len(instr_bytes)
    byte_index = 0
    byte = instr_bytes[byte_index]
    bytes_used = 0

    instruction_str = ""

    byte_is_prefix = is_prefix(byte)
    if byte_is_prefix:
        (prefix_bytes_used, prefix_str) = handle_prefix(byte)
        bytes_used += prefix_bytes_used
        instruction_str += prefix_str
        byte = instr_bytes[bytes_used]

    (byte_is_opcode, op_len) = is_opcode(instr_bytes[bytes_used:min(bytes_used+MAX_OPCODE_BYTES, total_bytes)])
    if byte_is_opcode:
        if op_len == 1:
            opcode_info = ONEB_GLOBAL_OPCODE_LIST[byte]
            (op_bytes_used, op_str) = handle_opcode(opcode_info, instr_bytes[bytes_used:total_bytes], orig_addr, bytes_used)
        elif op_len == 2:
            (op_bytes_used, op_str) = handle_twob_opcode(instr_bytes[bytes_used:total_bytes], orig_addr, bytes_used)
        elif op_len == 3:
            (op_bytes_used, op_str) = handle_threeb_opcode(instr_bytes[bytes_used:total_bytes], orig_addr)

        if op_bytes_used == 0:# actually an unknown op
            op_bytes_used = 1
            op_str = ""

        bytes_used += op_bytes_used
        instruction_str += op_str

    else:
        #TODO what if had prefix, but next byte isn't a known opcode?
        bytes_used = 1
        instruction_str = ""

    return (bytes_used, instruction_str)

def disassemble(bytes):
    INSTR_MAX_BYTES = 15
    
    num_bytes = len(bytes)

    output_list = {}

    byte_idx = 0
    while byte_idx < num_bytes:
        (num_used_bytes, instr_string) = disasm_instruction(bytes[byte_idx : byte_idx+INSTR_MAX_BYTES], byte_idx)
        
        if instr_string != "":#op is known
            address = format_address(byte_idx)

            formatted_str = format_instr(instr_string)
            
            output_list[address] = format_byte_str(bytes[byte_idx : byte_idx + num_used_bytes]) + " " + formatted_str
            byte_idx += num_used_bytes
        else:# op is unknown
            output_list[address] = format_unknown_instr_str(bytes[byte_idx] & 0xFF)
            byte_idx += 1

    printDisasm (output_list)

def getfile(filename):	
    with open(filename, "rb") as f:
        a = f.read()
    return a

def is_valid_file(parser, arg):
    fname = arg.strip()
    if not os.path.exists(fname):
        parser.error("The file {:s} does not exist!".format(fname))
    else:
        return open(fname, 'r')

def main():
    
    parser = argparse.ArgumentParser(description='Dissassemble an x86 binary starting at pos 0.')

    parser.add_argument('-i', type=str, required=True, dest="filename",\
                        help="x86 binary")
    
    args = parser.parse_args()

    filename = args.filename.strip()

    if is_valid_file(parser, filename):

        try: 
            bytes = getfile(filename)
        except IOError:
            parser.error("Could not open {:s}".format(filename))
            return

        disassemble(bytes)

if __name__ == "__main__":
    main()
