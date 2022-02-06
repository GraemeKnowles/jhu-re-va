#!/usr/bin/env python3
######################################################################
#
# Be sure to use python3...
#
# This is just an example to get you started if you are having
# difficulty starting the assignment. It is by no means the most
# efficient way to implement this disassembler, however, it is one
# that can easily be followed and extended to complete the requirements
#
# You may want to import other modules, but certainly not required
# This implements linear sweep..this can be modified to implement
# recursive descent as well
#
######################################################################
from pickle import FALSE
import sys
from enum import Enum
import struct

class OPCODE_LIST_INDEX_ENUM(Enum) :
    INSTR = 0
    REQ_RM = 1
    OP_EN = 2
    BASE_OP = 3
    OP_SIZE_BYTES = 4

#
# Key is the opcode
# value is a list of useful information
GLOBAL_OPCODE_LIST = {
    0x01 : ['add', True, 'mr'], 
    0x03 : ['add', True, 'rm'],
    0x05 : ['add eax,', False, 'id'],
    0x31 : ['xor', True, 'mr'],
    0x39 : ['cmp', True, 'mr'],
    0x74 : ['jz', False, 'd'],
    0x89 : ['mov', True, 'mr'],
    0x8b : ['mov', True, 'rm'],
    0xb8 : ['mov', False, 'oi', 0xb8, 4],
    0xc2 : ['retn', False, 'oi', 0xc2, 2],
    
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
    0x50 : ['push'],
    0x58 : ['pop']
}

LABELS = {

}

BYTEODER = 'little'

for reg in GLOBAL_REGISTER_NAMES:
    for op_val in OP_EN_O_OPS:
        entry = OP_EN_O_OPS[op_val]

        GLOBAL_OPCODE_LIST[op_val + reg.value] = [entry[0], False, 'o', op_val]

def isValidOpcode(opcode):
    if opcode in GLOBAL_OPCODE_LIST.keys():
        return True
    return False

def parseMODRM(modrm):
    mod = (modrm & 0xC0) >> 6
    reg = (modrm & 0x38) >> 3
    rm  = (modrm & 0x07)
    return (mod,reg,rm)

def printDisasm( l ):

    # Good idea to add a "global label" structure...
    # can check to see if "addr" is in it for a branch reference

    label_count = 0

    for addr in sorted(l):
        if addr in LABELS:
            print("LABEL_{d}:".format(label_count))
            label_count += 1

        print( '%s: %s' % (addr, l[addr]) )

def disassemble(b):

    ## TM
    # I would suggest maintaining an "output" dictionary
    # Your key should be the counter/address [you can use this
    # to print out labels easily]
    # and the value should be your disassembly output (or some
    # other data structure that can represent this..up to you )
    outputList = {}

    i = 0

    file_length = len(b)

    while i < file_length:

        implemented = False
        opcode = b[i]	#current byte to work on
        instruction_bytes = "%02x" % b[i]
        instruction = ''
        orig_index = i
        
        i += 1

        # Hint this is hear for a reason, but is this the only spot
        # such a check is required in?
        if i >= file_length:
           break

        if isValidOpcode( opcode ):
            print ('Found valid opcode')
            if 1:
                li = GLOBAL_OPCODE_LIST[opcode]
                print ('Index -> %d' % i )
                if li[OPCODE_LIST_INDEX_ENUM.REQ_RM.value] == True:
                    print ('REQUIRES MODRM BYTE')
                    #modrm = ord(b[i])
                    modrm = b[i]
                    instruction_bytes += ' '
                    #instruction_bytes += "%02x" % ord(b[i])
                    instruction_bytes += "%02x" % b[i]

                    i += 1 # we've consumed it now
                    mod,reg,rm = parseMODRM( modrm )

                    if mod == 3:
                        implemented = True
                        print ('r/m32 operand is direct register')
                        instruction += li[OPCODE_LIST_INDEX_ENUM.INSTR.value] + " "
                        if li[2] == 'mr':
                            instruction += GLOBAL_REGISTER_NAMES(rm).name
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES(reg).name
                        elif li[2] == 'rm':
                            instruction += GLOBAL_REGISTER_NAMES(reg).name
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES(rm).name

                    elif mod == 2:
                        implemented = True

                        last_op_idx = i+4
                        if last_op_idx >= file_length:
                            break
                        
                        operand_bytes = b[i:last_op_idx]
                        displacement = int.from_bytes(operand_bytes, BYTEODER)

                        instruction_bytes += " {:02x} {:02x} {:02x} {:02x}".format(*tuple(operand_bytes))
                        instruction = li[OPCODE_LIST_INDEX_ENUM.INSTR.value] + " " + GLOBAL_REGISTER_NAMES(reg).name
                        instruction += ", [" + GLOBAL_REGISTER_NAMES(rm).name + (" + 0%xh" % displacement) + "]"

                        outputList[ "%08X" % orig_index ] = instruction_bytes + " " + instruction

                        i += 4

                        #print ('r/m32 operand is [ reg + disp32 ] -> please implement')
                        # will need to parse the displacement32
                    elif mod == 1:
                        implemented = True
                        displacement = b[i]
                        i += 1
                        instruction_bytes += " {:02x}".format(displacement)

                        instruction = li[OPCODE_LIST_INDEX_ENUM.INSTR.value] + " " + GLOBAL_REGISTER_NAMES(reg).name
                        instruction += ", [" + GLOBAL_REGISTER_NAMES(rm).name + (" + {:02x}h".format(displacement)) + "]"

                       # print ('r/m32 operand is [ reg + disp8 ] -> please implement')
                        # will need to parse the displacement8
                    else:
                        if rm == 5:
                            print ('r/m32 operand is [disp32] -> please implement')
                        elif rm == 4:
                            print ('Indicates SIB byte required -> not required to implement')
                        else:
                            print ('r/m32 operand is [reg] -> please implement')

                    if implemented == True:
                        print ('Adding to list ' + instruction)
                        outputList[ "%08X" % orig_index ] = instruction_bytes + ' ' + instruction
                    else:
                        outputList[ "%08X" % orig_index ] = 'db %02x' % (int(opcode) & 0xff)
                else:
                    operand_encoding = li[OPCODE_LIST_INDEX_ENUM.OP_EN.value]
                    if operand_encoding == "o":
                        base_op = li[OPCODE_LIST_INDEX_ENUM.BASE_OP.value]
                        reg = GLOBAL_REGISTER_NAMES(opcode - base_op)
                        
                        instruction = li[OPCODE_LIST_INDEX_ENUM.INSTR.value] + " " + reg.name

                        print ('Adding to list ' + instruction)
                        outputList[ "%08X" % orig_index ] = instruction_bytes + ' ' + instruction

                    elif operand_encoding == "zo":
                        instruction = li[OPCODE_LIST_INDEX_ENUM.INSTR.value]
                        print ('Adding to list ' + instruction)
                        outputList[ "%08X" % orig_index ] = instruction_bytes + ' ' + instruction

                    elif operand_encoding == "oi":
                        # check if enough bytes to form operand
                        oper_num_bytes = li[OPCODE_LIST_INDEX_ENUM.OP_SIZE_BYTES.value]

                        last_op_idx = i+oper_num_bytes
                        if last_op_idx > file_length:
                            break
                        
                        operand_bytes = b[i:last_op_idx]
                        operand_32 = int.from_bytes(operand_bytes, BYTEODER)

                        # get 4 bytes
                        instruction_bytes += (" {:02x}" * oper_num_bytes).format(*tuple(operand_bytes))
                        instruction = li[OPCODE_LIST_INDEX_ENUM.INSTR.value] + (" 0%xh" % operand_32)

                        outputList[ "%08X" % orig_index ] = instruction_bytes + " " + instruction

                        i += oper_num_bytes
                    
                    elif operand_encoding == "d":
                        displacement = b[i]
                        i += 1

                        instruction_bytes += " {:02x}".format(displacement)
                        instruction = li[OPCODE_LIST_INDEX_ENUM.INSTR.value] + " {:02x}h".format(displacement) 
                        
                        outputList[ "%08X" % orig_index ] = instruction_bytes + " " + instruction

            #except:
            else:
                outputList[ "%08X" % orig_index ] = 'db %02x' % (int(opcode) & 0xff)
                i = orig_index
        else:
            outputList[ "%08X" % orig_index ] = 'db %02x' % (int(opcode) & 0xff)


    printDisasm (outputList)

def getfile(filename):	
    with open(filename, 'rb') as f:
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


if __name__ == '__main__':
    main()

