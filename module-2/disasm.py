from pickle import FALSE
from re import L
import sys
from enum import Enum
import queue

class OP_INFO_OFFSET(Enum) :
    BASE_OP = 0
    INSTR = 1
    REQ_RM = 2
    OP_EN = 3
    OP_SIZE_BYTES = 4
    NUM_ENTRIES = 5


# Key is the opcode
# value is a list of useful information
ONEB_GLOBAL_OPCODE_LIST = {
    0x01 : [0x01, "add", True, "mr"], 
    0x03 : [0x03, "add", True, "rm"],
    0x05 : [0x05, "add eax,", False, "oi", 4],#actually i
    0x31 : [0x31, "xor", True, "mr"],
    0x39 : [0x39, "cmp", True, "mr"],
    0x81 : [0x81, "add", True, "mi"],
    0x89 : [0x89, "mov", True, "mr"],
    0x8b : [0x8b, "mov", True, "rm"],
    0xb8 : [0xb8, "mov", False, "oi", 4],
    0xc2 : [0xc2, "retn", False, "oi", 2],
    0x33 : [0x33, "xor", True, "rm"]
}

TWOB_GLOBAL_OPCODE_LIST = {
    
}

THREEB_GLOBAL_OPCODE_LIST = {

}

JUMP_INSTR_LIST = {
    0xEB : [0xEB, "jmp", False, "d"],
    0xE9 : [0xE9, "jmp", False, "d"],
    0xFF : [0xFF, "jmp", True, "m"],
    0x74 : [0x74, "jz", False, "d", 1],
    0xE8 : [0xE8, "call", False, "d"],
    0xFF : [0xFF, "call", False, "d"]
}

for jmp in JUMP_INSTR_LIST:
    ONEB_GLOBAL_OPCODE_LIST[jmp] = JUMP_INSTR_LIST[jmp]

TWOB_JUMP_INSTR_LIST = {
    0x85 : [0x85, "jnz", False, "d", 4]
}

for jmp in TWOB_JUMP_INSTR_LIST:
    TWOB_GLOBAL_OPCODE_LIST[jmp] = TWOB_JUMP_INSTR_LIST[jmp]

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
    0x50 : ["push"],
    0x58 : ["pop"]
}

for reg in GLOBAL_REGISTER_NAMES:
    for op_val in OP_EN_O_OPS:
        entry = OP_EN_O_OPS[op_val]

        ONEB_GLOBAL_OPCODE_LIST[op_val + reg.value] = [op_val, entry[0], False, "o"]

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

def handle_prefix(byte):
    bytes_used = 1
    instruction_bytes = format_byte(byte)
    instruction_str = PREFIX_LIST[byte][PREFIX_LIST_INDEX_ENUM.PREFIX.value]
    return (bytes_used, instruction_bytes, instruction_str)

def format_byte(byte):
    return "{:02X}".format(byte)

def format_disp(disp):
    return "0x{:08X}h".format(disp)

def parse_int32(bytes):
    pass

def handle_sib(opcode_byte, opcode_info, bytes, orig_addr, modrm_tup):
    SIB_SPCL_CASE_BASE = 0b101
    SIB_SPCL_CASE_MOD = 0b00

    sib = bytes[0]
    bytes_used = 1
    (scale_bits, index_bits, base_bits) = parseSIB(sib)
    (mod, reg, rm) = modrm_tup

    instruction_bytes = [sib]

    if base_bits == SIB_SPCL_CASE_BASE and mod == SIB_SPCL_CASE_MOD:
        base_reg_str = " + " # no base register
        pass
    else:
        base_reg_str = " + " + GLOBAL_REGISTER_NAMES(reg).name + " + "

    scale = pow(2, scale_bits)
    index_reg = GLOBAL_REGISTER_NAMES(index_bits)

    last_op_idx = bytes_used + 4
    if last_op_idx >= len(bytes):
        return (False, 0, [], "")
    else:
        # parse the next 4 bytes
        operand_bytes = bytes[bytes_used:last_op_idx]
        instruction_bytes += operand_bytes
        displacement = format_disp(int.from_bytes(operand_bytes, BYTEODER))
        bytes_used += 4

    instruction_str = index_reg.name + " * "  + str(scale) + base_reg_str + displacement
    
    return (True, bytes_used, instruction_bytes, instruction_str)

def format_operands(encoding, operands):
    def format_operand(op):
        (op_str, is_mem, op_bytes) = op
        
        if is_mem:
            return "[" + op_str + "]"
        else:
            return op_str
    
    if encoding == "mr":
        op1 = operands[RM_KEY]
        op2 = operands[REG_KEY]
    elif encoding == "rm":
        op1 = operands[REG_KEY]
        op2 = operands[RM_KEY]
    elif encoding == "mi":
        op1 = operands[RM_KEY]
        op2 = operands[REG_KEY]
    else:
        print("Unkown operand encoding")
        op1 = ""
        op2 = ""


    return (format_operand(op1) + ", " + format_operand(op2), list(operands[REG_KEY][2]) + list(operands[RM_KEY][2]))

def get_operands(reg, mod, rm, opcode_info, bytes_used, opcode_byte, bytes, orig_addr):
    num_bytes = len(bytes)
    op_enc = opcode_info[OP_INFO_OFFSET.OP_EN.value]

    # elements are tuple (operand_str, is_mem, operand_bytes[])
    operands = {}
    valid_operands = True

    if mod == 3:
        if op_enc == "mi":
            last_op_idx = bytes_used + 4
            if last_op_idx >= num_bytes:
                valid_operands = False
            else:
                # parse the next 4 bytes
                operand_bytes = bytes[bytes_used:last_op_idx]
                immediate = int.from_bytes(operand_bytes, BYTEODER)
                bytes_used += 4

                operands[RM_KEY] = (GLOBAL_REGISTER_NAMES(rm).name, False, [])
                operands[REG_KEY] = (format_disp(immediate), False, operand_bytes)
        else:
            # Direct register access, no memory bytes
            operands[REG_KEY] = (GLOBAL_REGISTER_NAMES(reg).name, False, [])
            operands[RM_KEY] = (GLOBAL_REGISTER_NAMES(rm).name, False, [])

    elif mod == 2:
        #The r/m32 operand’s memory address is located in the r/m register + a 4-byte displacement.
        last_op_idx = bytes_used + 4
        if last_op_idx >= num_bytes:
            valid_operands = False
        else:
            # parse the next 4 bytes
            operand_bytes = bytes[bytes_used:last_op_idx]
            displacement = int.from_bytes(operand_bytes, BYTEODER)
            bytes_used += 4

            operands[REG_KEY] = (GLOBAL_REGISTER_NAMES(reg).name, False, [])
            operands[RM_KEY] = (GLOBAL_REGISTER_NAMES(rm).name + " + " + format_disp(displacement), True, operand_bytes)

    elif mod == 1:
        #The r/m32 operand’s memory address is located in the r/m register + a 1-byte displacement
        last_op_idx = bytes_used + 1
        if last_op_idx >= num_bytes:
            valid_operands = False
        else:
            # parse the next 4 bytes
            operand_bytes = bytes[bytes_used:last_op_idx]
            displacement = int.from_bytes(operand_bytes, BYTEODER)
            bytes_used += 1

            mem_str = GLOBAL_REGISTER_NAMES(rm).name + " + " + format_disp(displacement)
            reg_str = GLOBAL_REGISTER_NAMES(reg).name

            operands[REG_KEY] = (reg_str, False, [])
            operands[RM_KEY] = (mem_str, True, operand_bytes)

    else:# mod == 0
        #The r/m32 operand’s memory address is located in the r/m register
        if rm == 5:
            # SPECIAL CASE: If the MOD is 00 and the R/M value is 101,
            # this is a special case. This indicates the r/m32 location is a
            # memory location that is a displacement32 only

            if op_enc == "mi":
                last_op_idx = bytes_used + 8
                if last_op_idx >= num_bytes:
                    valid_operands = False
                else:
                    op_1_ed = bytes_used + 4
                    op_2_ed = op_1_ed + 4

                    # parse the next 4 bytes
                    op1_bytes = bytes[bytes_used:op_1_ed]
                    disp = int.from_bytes(op1_bytes, BYTEODER)
                    bytes_used += 4

                    # parse the next 4 bytes
                    op2_bytes = bytes[op_1_ed:op_2_ed]
                    immediate = int.from_bytes(op2_bytes, BYTEODER)
                    bytes_used += 4

                    operands[RM_KEY] = (format_disp(disp), True, op2_bytes)
                    operands[REG_KEY] = (format_disp(immediate), False, op1_bytes)
            else:
                last_op_idx = bytes_used + 4
                if last_op_idx >= num_bytes:
                    valid_operands = False
                else:
                    # parse the next 4 bytes
                    operand_bytes = bytes[bytes_used:last_op_idx]
                    displacement = int.from_bytes(operand_bytes, BYTEODER)
                    bytes_used += 4

                    operands[REG_KEY] = (GLOBAL_REGISTER_NAMES(reg).name, False, [])
                    operands[RM_KEY] = (format_disp(displacement), True, operand_bytes)

        elif rm == 4:
            # SIB byte is required
            (valid_operands, sib_bytes_used, sib_bytes, sib_str) = \
                handle_sib(opcode_byte, opcode_info, bytes, orig_addr, (mod, reg, rm))

            if valid_operands:
                bytes_used += sib_bytes_used
                operands[REG_KEY] = (GLOBAL_REGISTER_NAMES(reg).name, False, [])
                operands[RM_KEY] = (sib_str, True, sib_bytes)

            
        else: # rm == 0-3
            # r/m32 operand is [reg]
            operands[REG_KEY] = (GLOBAL_REGISTER_NAMES(reg).name, False, [])
            operands[RM_KEY] = (GLOBAL_REGISTER_NAMES(rm).name, True, [])
        

    return (valid_operands, operands, bytes_used)
    

def handle_modrm_instr(opcode_byte, opcode_info, bytes, orig_addr):
    bytes_used = 0

    # get modrm
    modrm = bytes[bytes_used]
    bytes_used += 1 # we've consumed it now
    mod,reg,rm = parseMODRM( modrm )
    op_enc = opcode_info[OP_INFO_OFFSET.OP_EN.value]

    instruction_bytes = format_byte(opcode_byte)
    instruction_bytes += format_byte(modrm)
    instruction_str = opcode_info[OP_INFO_OFFSET.INSTR.value] + " "

    (valid_operands, operands, op_bytes) = get_operands(reg, mod, rm, opcode_info, bytes_used, opcode_byte, bytes, orig_addr)
    bytes_used = op_bytes

    if valid_operands:
        (operands_str, operand_bytes) = format_operands(op_enc, operands)
        instruction_str += operands_str
        if len(operand_bytes) > 0:
            try:
                instruction_bytes += ("{:02X}" * len(operand_bytes)).format(*tuple(operand_bytes))
            except ValueError:
                pass

    return (bytes_used, instruction_bytes, instruction_str)

def handle_nonrm_instr(opcode_byte, opcode_info, bytes, orig_addr, total_instr_bytes):
    num_bytes = len(bytes)
    bytes_used = 0

    instruction_bytes = ""
    instruction_str = ""

    operand_encoding = opcode_info[OP_INFO_OFFSET.OP_EN.value]
    if operand_encoding == "o":
        base_op = opcode_info[OP_INFO_OFFSET.BASE_OP.value]
        reg = GLOBAL_REGISTER_NAMES(opcode_byte - base_op)
        instruction_bytes = format_byte(opcode_byte)
        instruction_str = opcode_info[OP_INFO_OFFSET.INSTR.value] + " " + reg.name

    elif operand_encoding == "zo":
        instruction_bytes = format_byte(opcode_byte)
        instruction_str = opcode_info[OP_INFO_OFFSET.INSTR.value]

    elif operand_encoding == "oi":
        # check if enough bytes to form operand
        oper_num_bytes = opcode_info[OP_INFO_OFFSET.OP_SIZE_BYTES.value]

        last_op_idx = bytes_used+oper_num_bytes
        if last_op_idx > num_bytes:
            return (bytes_used, instruction_bytes, instruction_str)

        operand_bytes = bytes[bytes_used:last_op_idx]
        operand_32 = int.from_bytes(operand_bytes, BYTEODER)

        instruction_bytes += format_byte(opcode_byte)
        instruction_bytes += ("{:02X}" * oper_num_bytes).format(*tuple(operand_bytes))
        instruction_str = opcode_info[OP_INFO_OFFSET.INSTR.value] + (" 0%Xh" % operand_32)

        bytes_used += oper_num_bytes
    
    elif operand_encoding == "d":
        displacement = bytes[bytes_used]
        bytes_used += 1

        displacement_str = format_byte(opcode_byte) + format_byte(displacement)
        instruction_bytes += displacement_str
        instruction_str = opcode_info[OP_INFO_OFFSET.INSTR.value] + " "

        if is_jump(opcode_info[OP_INFO_OFFSET.BASE_OP.value]):
            target = orig_addr + displacement + total_instr_bytes + bytes_used
            LABELS[target] = format_label(target)
            instruction_str += LABELS[target]
        else:
            instruction_str += displacement_str + "h"
    else:
        # unknown encoding, do the db xx
        pass

    return (bytes_used, instruction_bytes, instruction_str)

def handle_opcode(opcode_info, bytes, orig_addr, bytes_used):
    num_bytes = len(bytes)
    opcode_byte = bytes[0]

    bytes_used = 1
    instruction_bytes = format_byte(opcode_byte)
    instruction_str = ""

    instr_bytes_used = 0

    if opcode_info[OP_INFO_OFFSET.REQ_RM.value] == True:
        (instr_bytes_used, instruction_bytes, instruction_str) = handle_modrm_instr(opcode_byte, opcode_info, bytes[bytes_used:num_bytes], orig_addr)
    else:
        (instr_bytes_used, instruction_bytes, instruction_str) = handle_nonrm_instr(opcode_byte, opcode_info, bytes[bytes_used:num_bytes], orig_addr, bytes_used)

    bytes_used += instr_bytes_used

    return (bytes_used, instruction_bytes, instruction_str)

def handle_twob_opcode(bytes, orig_addr, bytes_used):
    num_bytes = len(bytes)

    if num_bytes >= 2:
        opcode_info = TWOB_GLOBAL_OPCODE_LIST[bytes[1]]
        (bytes_used, instruction_bytes, instruction_str) = handle_opcode(opcode_info, bytes[1:num_bytes], orig_addr, bytes_used)
        return (bytes_used + 1, instruction_bytes + format_byte(bytes[0]), instruction_str)

    return (0, "", "")

def handle_threeb_opcode(bytes, orig_addr):
    num_bytes = len(bytes)

    if num_bytes >= 3:
        opcode_info = THREEB_GLOBAL_OPCODE_LIST[bytes[2]]
        (bytes_used, instruction_bytes, instruction_str) = handle_opcode(bytes[2:num_bytes], orig_addr)
        return (bytes_used + 2, format_byte(bytes[0]) + format_byte(bytes[1]) + instruction_bytes, instruction_str)

    return (0, "", "")


def disasm_instruction(instr_bytes, orig_addr):
    total_bytes = len(instr_bytes)
    byte_index = 0
    byte = instr_bytes[byte_index]
    bytes_used = 0

    instruction_bytes = ""
    instruction_str = ""

    byte_is_prefix = is_prefix(byte)
    if byte_is_prefix:
        (prefix_bytes_used, prefix_bytes, prefix_str) = handle_prefix(byte)
        bytes_used += prefix_bytes_used
        instruction_bytes += prefix_bytes
        instruction_str += prefix_str
        byte = instr_bytes[bytes_used]

    (byte_is_opcode, op_len) = is_opcode(instr_bytes[bytes_used:min(bytes_used+MAX_OPCODE_BYTES, total_bytes)])
    if byte_is_opcode:
        if op_len == 1:
            opcode_info = ONEB_GLOBAL_OPCODE_LIST[byte]
            (op_bytes_used, op_bytes, op_str) = handle_opcode(opcode_info, instr_bytes[bytes_used:total_bytes], orig_addr, bytes_used)
        elif op_len == 2:
            (op_bytes_used, op_bytes, op_str) = handle_twob_opcode(instr_bytes[bytes_used:total_bytes], orig_addr, bytes_used)
        elif op_len == 3:
            (op_bytes_used, op_bytes, op_str) = handle_threeb_opcode(instr_bytes[bytes_used:total_bytes], orig_addr)

        bytes_used += op_bytes_used
        instruction_bytes += op_bytes
        instruction_str += op_str

    else:
        #TODO what if had prefix, but next byte isn't a known opcode?
        bytes_used += 1
        instruction_bytes = ""
        instruction_str = "db {:02X}".format(byte & 0xff)

    return (bytes_used, instruction_bytes, instruction_str)

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

def format_byte_str(instr_str):
    return "{:<18s}".format(instr_str)

def disassemble(bytes):
    INSTR_MAX_BYTES = 15
    
    num_bytes = len(bytes)

    output_list = {}

    byte_idx = 0
    while byte_idx < num_bytes:
        (num_used_bytes, instr_bytes, instr_string) = disasm_instruction(bytes[byte_idx : byte_idx+INSTR_MAX_BYTES], byte_idx)
        address = format_address(byte_idx)

        formatted_str = format_instr(instr_string)
        
        if instr_bytes == "":
            output_list[address] = formatted_str
        else:
            output_list[address] = format_byte_str(instr_bytes) + " " + formatted_str
        
        byte_idx += num_used_bytes

    printDisasm (output_list)

def getfile(filename):	
    with open(filename, "rb") as f:
        a = f.read()
    return a		

def main():
    import sys 
    if len(sys.argv) < 2:
        print ("Please enter filename.")
        sys.exit(0)
    else:
        binary = getfile(sys.argv[1])

    disassemble(binary)


if __name__ == "__main__":
    main()
