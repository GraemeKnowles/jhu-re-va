# 695.744 - Programming Assignment #1
# Graeme Knowles

from enum import Enum
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

# Holds information about the operands of a given instruction
class OpInfo() :
    
    def __init__(self, base_op : int, instr_str : str, req_rm : bool, encoding : str, op_types_arr : OpTypes, ext : str, imm_len : int, valid_mod):
        self.base_op = base_op
        self.instr = instr_str
        self.req_rm = req_rm
        self.encoding = encoding
        self.op_types = op_types_arr
        self.ext = ext
        self.imm_len = imm_len
        self.valid_mod = valid_mod

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

# holds all one byte opcodes
ONEB_GLOBAL_OPCODE_LIST = {

}

# adds an opcode and operand info to target list
def _add_opinfo_to_list(list, op_code, op_info):
    if op_code in list:
        exist = list[op_code]
        exist.append(op_info)
        list[op_code] = exist
    else:
        list[op_code] = [op_info]

# adds an opcode to a target list.
def _add_op_to_list(list, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod = {0, 1, 2, 3}):
    _add_opinfo_to_list(list, op_code, OpInfo(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod))

# add a one byte instruction to the appropriate lists
def _add_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm, valid_mod = {0, 1, 2, 3}):
    _add_op_to_list(ONEB_GLOBAL_OPCODE_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm, valid_mod)

# add all supported one byte instructions
_add_op(0x01, "add", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x03, "add", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
_add_op(0x05, "add eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0x25, "and eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0x81, "and", True, "mi", [OpTypes.RM, OpTypes.Immediate], "4", DEF_OP_SIZE)
_add_op(0x21, "and", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x23, "and", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", DEF_OP_SIZE)
_add_op(0x39, "cmp", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x81, "add", True, "mi", [OpTypes.RM, OpTypes.Immediate], "0", DEF_OP_SIZE)
_add_op(0x89, "mov", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x8b, "mov", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
_add_op(0x3D, "cmp", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0x81, "cmp", True, "mi", [OpTypes.RM, OpTypes.Immediate], "7", DEF_OP_SIZE)
_add_op(0x3B, "cmp", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
_add_op(0xFF, "dec", True, "m", [OpTypes.RM], "1", 0)
_add_op(0xF7, "idiv", True, "m", [OpTypes.RM], "7", 0)
_add_op(0xFF, "inc", True, "m", [OpTypes.RM], "0", 0)
_add_op(0x8D, "lea", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
_add_op(0xC7, "mov", True, "mi", [OpTypes.RM, OpTypes.Immediate], "0", DEF_OP_SIZE)
_add_op(0xA5, "movsd", False, "zo", [], "", 0)
_add_op(0x90, "nop", False, "zo", [], "", 0)
_add_op(0xF7, "not", True, "m", [OpTypes.RM], "2",0)
_add_op(0x0D, "or eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0x81, "or", True, "mi", [OpTypes.RM, OpTypes.Immediate], "1", DEF_OP_SIZE)
_add_op(0x09, "or", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x0B, "or", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
_add_op(0x8F, "pop", True, "m", [OpTypes.RM], "0", 0)
_add_op(0xFF, "push", True, "m", [OpTypes.RM], "6", 0)
_add_op(0x68, "push", False, "i", [OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0xA7, "cmpsd", False, "zo", [], "", 0)
_add_op(0xCB, "retf", False, "zo", [], "", 0)
_add_op(0xCA, "retf", False, "i", [OpTypes.Immediate], "", 2)
_add_op(0xC2, "retn", False, "i", [OpTypes.Immediate], "", 2)
_add_op(0xC3, "retn", False, "zo", [], "", 0)
_add_op(0x2D, "sub eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0x81, "sub", True, "mi", [OpTypes.RM, OpTypes.Immediate], "5", DEF_OP_SIZE)
_add_op(0x29, "sub", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x2B, "sub", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)
_add_op(0xA9, "test eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0xF7, "test", True, "mi", [OpTypes.RM, OpTypes.Immediate], "0", DEF_OP_SIZE)
_add_op(0x85, "test", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x35, "xor eax", False, "i", [OpTypes.Included, OpTypes.Immediate], "", DEF_OP_SIZE)
_add_op(0x81, "xor", True, "mi", [OpTypes.RM, OpTypes.Immediate], "6", DEF_OP_SIZE)
_add_op(0x31, "xor", True, "mr", [OpTypes.RM, OpTypes.Reg], "r", 0)
_add_op(0x33, "xor", True, "rm", [OpTypes.Reg, OpTypes.RM], "r", 0)

# holds all supported two byte instructions
TWOB_GLOBAL_OPCODE_LIST = {
    
}

# adds a two byte opcode to the appropriate lists
def _add_twob_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod = {0, 1, 2, 3}):
    _add_op_to_list(TWOB_GLOBAL_OPCODE_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod)

# add all supported two byte instructions
_add_twob_op(0xAE, "clflush", False, "m", [OpTypes.RM], "0", 0)

# holds all opcodes that are three bytes
THREEB_GLOBAL_OPCODE_LIST = {

}

# Holds all one byte jump instructions
JUMP_INSTR_LIST = {

}

# adds a one byte jump instruction to the appropriate lists
def _add_jmp_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod = {0, 1, 2, 3}):
    _add_op_to_list(JUMP_INSTR_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod)
    _add_op(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod)

# all all supported one byte jump operations
_add_jmp_op(0xEB, "jmp", False, "d", [OpTypes.Immediate], "", 1)
_add_jmp_op(0xE9, "jmp", False, "d", [OpTypes.Immediate], "", DEF_OP_SIZE)
_add_jmp_op(0xFF, "jmp", True, "m", [OpTypes.RM], "4", 0)
_add_jmp_op(0x74, "jz", False, "d", [OpTypes.Immediate], "", 1)
_add_jmp_op(0x75, "jz", False, "d", [OpTypes.Immediate], "", 1)
_add_jmp_op(0xE8, "call", False, "d", [OpTypes.Immediate], "", DEF_OP_SIZE)
_add_jmp_op(0xFF, "call", True, "d", [OpTypes.RM], "2", DEF_OP_SIZE)

# holds all two byte jump instructions
TWOB_JUMP_INSTR_LIST = {

}

# adds a two byte jump to the list
def _add_twob_jump(op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod = {0, 1, 2, 3}):
    _add_op_to_list(TWOB_JUMP_INSTR_LIST, op_code, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod)

# add all supported jumps that are two bytes
_add_twob_jump(0x84, "jnz", False, "d", [OpTypes.Immediate], "", 4)
_add_twob_jump(0x85, "jz", False, "d", [OpTypes.Immediate], "",  4)

MAX_OPCODE_BYTES = 3# maximum number of bytes an opcode could be
TWO_BYTE_OPCODE = 0xF# opcode that denotes a 2 byte opcode
THREE_BYTE_OPCODE_1 = 0x38# opcode that denotes a 3 byte opcode
THREE_BYTE_OPCODE_2 = 0x39# opcode that denoates a 3 byte opcode

# indices into the prefix information list
class PREFIX_LIST_INDEX_ENUM(Enum) :
    PREFIX = 0

# Supported prefixes
PREFIX_LIST = {
    0xF2 : ["repne"]
}

# Register names and numbers
class GLOBAL_REGISTER_NAMES(Enum) : 
    eax = 0
    ecx = 1
    edx = 2
    ebx = 3
    esp = 4
    ebp = 5
    esi = 6
    edi = 7

# Used to generate opcodes that use opcode + rd
OP_EN_O_OPS = {
    0x50 : ["push", "o", [OpTypes.RD], "", 0],
    0x58 : ["pop", "o", [OpTypes.RD], "", 0],
    0xB8 : ["mov", "oi", [OpTypes.RD, OpTypes.Immediate], "", DEF_OP_SIZE],
    0x48 : ["dec", "i", [OpTypes.RD], "1", 0],
    0x40 : ["inc", "o", [OpTypes.RD], "", 0]
}

# adds an instruction that takes an rd operand to the list
def _add_op_rd(op_code, base_op, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod = {0, 1, 2, 3}):
    opinf = OpInfo(base_op, instr_str, req_rm, encoding, op_types_arr, ext, imm_len, valid_mod)
    _add_opinfo_to_list(ONEB_GLOBAL_OPCODE_LIST, op_code, opinf)

# For the operands that add the register value to the operand
# generate the instruction for each register and add them to the list
for reg in GLOBAL_REGISTER_NAMES:
    for op_val in OP_EN_O_OPS:
        entry = OP_EN_O_OPS[op_val]
        _add_op_rd(op_val + reg.value, op_val, entry[0], False, entry[1], entry[2], entry[3], entry[4])

# endianness of operands
BYTEODER = "little"

# Holds jump labels defined by a calculable displacement
LABELS = {

}

# Special case where the [*] nomenclature means a disp32 
# with no base if the MOD is 00B. Otherwise, [*] means 
# disp8 or disp32 + [EBP].
SIB_SPCL_CASE_BASE = 5
SIB_SPCL_CASE_MOD = 0

# checks if known prefix
def _is_prefix(prefix):
    return prefix in PREFIX_LIST.keys()

# check if known opcode, handles one, two and three bytes
def _is_opcode(opcode):
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

# checks if known jump
def _is_jump(opcode):
    return opcode in JUMP_INSTR_LIST or opcode in TWOB_JUMP_INSTR_LIST

# parses out mod, reg, and rm bits
def _parseMODRM(modrm):
    mod = (modrm & 0xC0) >> 6
    reg = (modrm & 0x38) >> 3
    rm  = (modrm & 0x07)
    return (mod, reg, rm)

# parses a SIB byte
def _parseSIB(sib):
    return _parseMODRM(sib)# same format

# checks if an instruction has a sib
def _hasSIB(mod, rm):
    return rm == 4 and (mod == 0 or mod == 1 or mod == 2)

# formats a single byte - hex
def _format_byte_hex(byte):
    return "0x{:02X}h".format(byte)

# formats a word (4 bytes) - hex
def _format_word_hex(word):
    return "0x{:04X}h".format(word)

# formats a dword (8 bytes) - hex
def _format_dword_hex(dword):
    return "0x{:08X}h".format(dword)

# formats a label for output
def _format_label(addr):
    return "offset_{:08X}h".format(addr)

# prints final disassembled text
def _printDisasm( l ):
    for addr in sorted(l):
        # check if address has a label
        int_addr = int(addr, 16)
        if int_addr in LABELS:
            print(LABELS[int_addr] + ":")

        print( "%s: %s" % (addr, l[addr]) )

# formats an address for output
def _format_address(byte_idx):
    return "{:08X}".format(byte_idx)

# formats an instruction for output
def _format_instr_str(instr_str):
    return "{:<22s}".format(instr_str)

# formats a list of bytes
def _format_byte_str(bytes_str):
    return "{:<22s}".format(''.join('{:02X}'.format(x) for x in bytes_str))

# formats a prefix for output
def _handle_prefix(byte):
    bytes_used = 1
    instruction_str = PREFIX_LIST[byte][PREFIX_LIST_INDEX_ENUM.PREFIX.value]
    return (bytes_used, instruction_str)

# formats a register operand for output
def _handle_reg(opinfo : OpInfo, instr : Instruction) -> str:
    return GLOBAL_REGISTER_NAMES(instr.reg).name

# formats an rm operand for output
def _handle_rm(opinfo : OpInfo, instr : Instruction) -> str:
    
    # check if SIB addressing is required
    if _hasSIB(instr.mod, instr.rm):
        return _handle_sibrm(opinfo, instr)

    if instr.mod == 3:
        # print ('r/m32 operand is direct register')
        return GLOBAL_REGISTER_NAMES(instr.rm).name

    elif instr.mod == 2:
        # r/m32 operand is [ reg + disp32 ]
        if instr.disp > 0:
            return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + " + " + _format_dword_hex(instr.disp) + "]"
        else:
            return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + "]"

    elif instr.mod == 1:
        # r/m32 operand is [ reg + disp8 ]
        if instr.disp > 0:
            return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + " + " + _format_byte_hex(instr.disp) + "]"
        else:
            return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + "]"

    else:
        if instr.rm == 5:
            # r/m32 operand is [disp32]
            return "[" + _format_dword_hex(instr.disp) + "]"

        elif instr.rm == 4:
            # Indicates SIB byte required
            return _handle_sibrm(opinfo, instr)
            
        else:# rm == 0-3
            # r/m32 operand is [reg]
            return "[" + GLOBAL_REGISTER_NAMES(instr.rm).name + "]"
            
# format sib operand addressing for output
def _handle_sibrm(opinfo : OpInfo, instr : Instruction) -> str:
    sib_str = ""

    # Print base register, check for special case w/ no base
    if not (instr.base == SIB_SPCL_CASE_BASE and instr.mod == SIB_SPCL_CASE_MOD):
        sib_str += GLOBAL_REGISTER_NAMES(instr.base).name

    # Print index register and scale, ESP can't be scaled
    if instr.base != GLOBAL_REGISTER_NAMES.esp.value:
        scale = pow(2, instr.scale)

        if sib_str != "":
            sib_str += " + "

        sib_str += GLOBAL_REGISTER_NAMES(instr.index).name

        # only print scale if not *1
        if scale > 1:
             sib_str += " * " + str(scale)

    if sib_str != "":
        op_str = " + "
    
    # only print displacement if not 0
    if instr.disp != 0:
        sib_str += op_str + _format_dword_hex(instr.disp)

    return "[" + sib_str + "]"


# handles an operand who is already included
def _handle_included(opinfo : OpInfo, instr : Instruction) -> str:
    return ""

# format an immediate operand for output
def _handle_immediate(opinfo : OpInfo, instr : Instruction) -> str:
    # check if a jump to a known address
    if _is_jump(opinfo.base_op):
        target = (instr.orig_addr + instr.imm + instr.total_len) & 0xFFFFFFFF
        LABELS[target] = _format_label(target)
        return LABELS[target]
    else:
        return _format_dword_hex(instr.imm)

# format an opcode + register opcode
def _handle_rd(opinfo : OpInfo, instr : Instruction) -> str:
    return GLOBAL_REGISTER_NAMES(instr.op - opinfo.base_op).name

# lookup for handlers for different types of operands
OPERAND_HANDLERS = {
    OpTypes.Reg : _handle_reg,
    OpTypes.RM : _handle_rm,
    OpTypes.Included : _handle_included,
    OpTypes.Immediate : _handle_immediate,
    OpTypes.RD : _handle_rd
}

# Parses and validates an opcode and byte list into an Instruction and OpInfo
def _parse_instruction(opcode_info_list, bytes, orig_addr, prefix_bytes) -> Tuple[int, Instruction, OpInfo]:
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

    # determine correct opcode
    poss_opcodes = len(opcode_info_list)
    if poss_opcodes > 1:
        if num_bytes >= 2:
            # opcode has a /ext and need to pick correct one
            # every op with /ext requires modrm
            (m, r, rm) = _parseMODRM(bytes[1])
            reg_str = str(r)
            def condition(x : OpInfo): return x.ext == reg_str
            idx_of_op = [idx for idx, element in enumerate(opcode_info_list) if condition(element)]
            
            if len(idx_of_op) == 0:
                # unknown op
                return (0, None, None)
            if len(idx_of_op) > 1:
                return (0, None, None)#This is a setup error, multiple ops with same ext
            else:
                opinfo = opcode_info_list[idx_of_op[0]]
        else:
            # note enough remaining bytes, every /ext requires modrm
            return (0, None, None)
    elif poss_opcodes == 1:
        opinfo = opcode_info_list[0]
    else:
        # unknown operation
        return (0, None, None)
    
    # how many bytes the displacement is (if any)
    modrm_disp_bytes = 0
    has_sib = False

    # if op requires modrm, parse it
    if opinfo.req_rm:
        # ensure enough bytes left
        if bytes_used >= num_bytes:
            return (0, None, None)

        (mod, reg, rm) = _parseMODRM(bytes[bytes_used])
        bytes_used += 1
        
        # check if valid operand mode
        if not (mod in opinfo.valid_mod):
            return (0, None, None)

        # check if instruction has displacement
        if mod == 1:
            modrm_disp_bytes = 1
        elif mod == 2 or (mod == 0 and rm == 5):
            modrm_disp_bytes = 4
            
        # if it has modrm, it may have sib
        if _hasSIB(mod, rm):
            # check if enough bytes left
            if bytes_used >= num_bytes:
                return (0, None, None)

            (scale, index, base) = _parseSIB(bytes[bytes_used])
            bytes_used += 1

            # special case the "[*]" - disp32 with no base
            if mod == SIB_SPCL_CASE_MOD and base == SIB_SPCL_CASE_BASE:
                modrm_disp_bytes = 4
            
    # parse displacement if any
    if modrm_disp_bytes > 0:
        # make sure enough bytes left
        if bytes_used + modrm_disp_bytes - 1 > num_bytes:
            return (0, None, None)

        # parse displacement
        disp = int.from_bytes(bytes[bytes_used:bytes_used + modrm_disp_bytes], BYTEODER)
        bytes_used += modrm_disp_bytes

    # parse immediate if any
    if OpTypes.Immediate in opinfo.op_types:
        # make sure enough bytes left
        if bytes_used + opinfo.imm_len - 1 > num_bytes:
            return (0, None, None)

        # parse immediate
        imm = int.from_bytes(bytes[bytes_used:bytes_used + opinfo.imm_len], BYTEODER)
        bytes_used += opinfo.imm_len

    # build parsed instruction
    instr = Instruction(prefix, opcode_byte, \
        mod, reg, rm, scale, index, base, disp, \
        modrm_disp_bytes, imm, orig_addr, \
        bytes_used + prefix_bytes, has_sib)
    
    return (bytes_used, instr, opinfo)

# parses a complete instruction and handles formatting the output
# string for its operands.
def _handle_opcode(opcode_info_lst : OpInfo, bytes, orig_addr, bytes_used):
    # parse out all parts of the instruction
    (instr_len, instruction, opinfo) = _parse_instruction(opcode_info_lst, bytes, orig_addr, bytes_used)

    # check for unknown/invalid instruction
    if instr_len <= 0:
        return (0, "")

    # add the opcode string
    instr_str = opinfo.instr

    # add extra space for opcodes ops that have an included operand
    if len(opinfo.op_types) > 0 and opinfo.op_types[0] != OpTypes.Included:
        instr_str += " "

    # iterate though the operands in order
    for idx, op_type in enumerate(opinfo.op_types):
        # check if operand type known
        if op_type in OPERAND_HANDLERS:
            # lookup and call handler for operand
            instr_str += OPERAND_HANDLERS[op_type](opinfo, instruction)
            # don't add comma at the end of the string
            if idx < len(opinfo.op_types) - 1:
                instr_str += ", "
        else:
            return (0, "")

    return (instr_len, instr_str)

# handles a two byte opcode
def _handle_twob_opcode(bytes, orig_addr, bytes_used):
    num_bytes = len(bytes)

    if num_bytes >= 2:
        opcode_info = TWOB_GLOBAL_OPCODE_LIST[bytes[1]]
        (bytes_used, instruction_str) = _handle_opcode(opcode_info, bytes[1:num_bytes], orig_addr, bytes_used)
        return (bytes_used + 1, instruction_str)

    return (0, "", "")

# handles a three byte opcode
def _handle_threeb_opcode(bytes, orig_addr):
    num_bytes = len(bytes)

    if num_bytes >= 3:
        opcode_info = THREEB_GLOBAL_OPCODE_LIST[bytes[2]]
        (bytes_used, instruction_str) = _handle_opcode(bytes[2:num_bytes], orig_addr)
        return (bytes_used + 2, instruction_str)

    return (0, "", "")

# when a byte is unknown, print special string
def _format_unknown_instr_str(byte):
    return "db {:02X}".format(byte & 0xff)

# disassembles an instruction beginning at instr_bytes[0]
def _disasm_instruction(instr_bytes, orig_addr):
    total_bytes = len(instr_bytes)
    byte_index = 0
    byte = instr_bytes[byte_index]
    bytes_used = 0

    instruction_str = ""

    # check if it has on or more prefixes
    while _is_prefix(byte):
        (prefix_bytes_used, prefix_str) = _handle_prefix(byte)
        bytes_used += prefix_bytes_used
        instruction_str += prefix_str
        byte = instr_bytes[bytes_used]

    # check if it's a valid opcode
    (byte_is_opcode, op_len) = _is_opcode(instr_bytes[bytes_used:min(bytes_used+MAX_OPCODE_BYTES, total_bytes)])
    if byte_is_opcode:
        if op_len == 1:# one byte opcode
            opcode_info = ONEB_GLOBAL_OPCODE_LIST[byte]
            (op_bytes_used, op_str) = _handle_opcode(opcode_info, instr_bytes[bytes_used:total_bytes], orig_addr, bytes_used)
        elif op_len == 2:# two byte opcode
            (op_bytes_used, op_str) = _handle_twob_opcode(instr_bytes[bytes_used:total_bytes], orig_addr, bytes_used)
        elif op_len == 3:# three byte opcode
            (op_bytes_used, op_str) = _handle_threeb_opcode(instr_bytes[bytes_used:total_bytes], orig_addr)

        if op_bytes_used == 0:# actually an unknown op
            op_bytes_used = 1# skip this byte
            op_str = ""# set invalid

        bytes_used += op_bytes_used
        instruction_str += op_str

    else:
        # invalid opcode
        bytes_used = 1# skip first byte (prefix, if it had a valid one)
        instruction_str = ""# set invalid

    return (bytes_used, instruction_str)

# disassembles a string of bytes. Assumes instructions start at address 0
def disassemble(bytes):
    INSTR_MAX_BYTES = 15# maximum possible bytes for an instruction
    num_bytes = len(bytes)# total number of bytes for the file

    # holds the disassmbled instructions using address as key
    output_list = {}

    byte_idx = 0
    while byte_idx < num_bytes:
        # attempt to disassemble every byte
        (num_used_bytes, instr_string) = _disasm_instruction(bytes[byte_idx : byte_idx+INSTR_MAX_BYTES], byte_idx)
        
        address = _format_address(byte_idx)

        if instr_string != "":#op is known
            # format the instruction op1, op.. part
            formatted_str = _format_instr_str(instr_string)
            
            # add the final string to the output at original address
            output_list[address] = _format_byte_str(bytes[byte_idx : byte_idx + num_used_bytes]) + " " + formatted_str
            byte_idx += num_used_bytes
        else:# op is unknown
            output_list[address] = _format_unknown_instr_str(bytes[byte_idx] & 0xFF)
            byte_idx += 1

    # print the complete listing
    _printDisasm (output_list)

# opens a file and reads the bytes, returns a bytestring
def getfile(filename):	
    with open(filename, "rb") as f:
        a = f.read()
    return a

# checks if file exists and readable
def is_valid_file(parser, arg):
    fname = arg.strip()
    if not os.path.exists(fname):
        parser.error("The file {:s} does not exist!".format(fname))
    else:
        return open(fname, 'r')

# Runs the command line program to disassemble an x86 input file
def main():
    # Set up argument parser, and set description
    parser = argparse.ArgumentParser(description='Dissassemble an x86 binary starting at pos 0.')
    # input file argument
    parser.add_argument('-i', type=str, required=True, dest="filename",\
                        help="x86 binary")
    
    args = parser.parse_args()

    # get filename, strip extra whitespace
    filename = args.filename.strip()

    # check if file exists
    if is_valid_file(parser, filename):

        try: 
            bytes = getfile(filename)# attempt to open and read file
        except IOError:
            parser.error("Could not open {:s}".format(filename))

        disassemble(bytes)

if __name__ == "__main__":
    main()
