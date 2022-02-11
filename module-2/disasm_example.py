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
import sys


#
# Key is the opcode
# value is a list of useful information
GLOBAL_OPCODE_LIST = {
    0x05 : ['add eax, ', False, 'id' ],
    0x01 : ['add ', True, 'mr'], 
    0x03 : ['add ', True, 'rm'],
}

GLOBAL_REGISTER_NAMES = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]

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

    for addr in sorted(l):
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

    while i < len(b):

        implemented = False
        #opcode = ord(b[i])	#If using python2.7
        opcode = b[i]	#current byte to work on
        #instruction_bytes = "%02x" % ord(b[i]) # if using python 2.7
        instruction_bytes = "%02x" % b[i]
        instruction = ''
        orig_index = i
        
        i += 1

        # Hint this is hear for a reason, but is this the only spot
        # such a check is required in?
        if i >= len(b):
           break

        

        if isValidOpcode( opcode ):
            print ('Found valid opcode')
            if 1:
                li = GLOBAL_OPCODE_LIST[opcode]
                print ('Index -> %d' % i )
                if li[1] == True:
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
                        instruction += li[0]
                        if li[2] == 'mr':
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                        elif li[2] == 'rm':
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[rm]

                    elif mod == 2:
                        print ('r/m32 operand is [ reg + disp32 ] -> please implement')
                        # will need to parse the displacement32
                    elif mod == 1:
                        print ('r/m32 operand is [ reg + disp8 ] -> please implement')
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
                    print ('Does not require MODRM - modify to complete the instruction and consume the appropriate bytes')
                    outputList[ "%08X" % orig_index ] = 'db %02x' % (int(opcode) & 0xff)
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

