[BITS 32]

;add eax, imm32 0x05 id
add eax, 0x12345678

;add r/m32, imm32, 0x81 /0 id, 00/01/10/11
add ecx, 0x33333333 
add [ecx], dword 0x33333333
add [ecx + 0x33333333], dword 0x33333333
add [ecx + 0x33], dword 0x33333333
add [0x33333333], dword 0x33333333
add [ecx * 2 + 0x33333333], ecx
add [ecx * 2 + esi + 0x33333333], ecx

;add r/m32, r32, 0x01 /r 00/01/10/11
add ecx, eax 
add [eax], eax
add [ecx], eax
add [ecx + 0x33333333], eax
add [ecx + 0x33], eax
add [0x33333333], eax
add [ecx * 2 + 0x33333333], ecx
add [ecx * 2 + esi + 0x33333333], ecx

;add r32, r/m32 0x03 /r 00/01/10/11
add eax, eax
add eax, [eax]
add eax, [ecx + 0x33333333]
add eax, [ecx + 0x33]
add eax, [0x33333333]
add ecx, [ecx * 2 + 0x33333333]
add ecx, [ecx * 2 + esi + 0x33333333]

;and eax, imm32 0x25 id MODR/M Not Required
and eax, 0x12345678

;and r/m32, imm32 0x81 /4 id 00/01/10/11
and ecx, 0x33333333 
and [ecx], dword 0x33333333
and [ecx + 0x33333333], dword 0x33333333
and [ecx + 0x33], dword 0x33333333
and [0x33333333], dword 0x33333333
and [ecx * 2 + 0x33333333], ecx
and [ecx * 2 + esi + 0x33333333], ecx

;and r/m32, r32 0x21 /r 00/01/10/11
and ecx, eax 
and [eax], eax
and [ecx], eax
and [ecx + 0x33333333], eax
and [ecx + 0x33], eax
and [0x33333333], eax
and [ecx * 2 + 0x33333333], ecx
and [ecx * 2 + esi + 0x33333333], ecx

;and r32, r/m32 0x23 /r 00/01/10/11
and eax, eax
and eax, [eax]
and eax, [ecx + 0x33333333]
and eax, [ecx + 0x33]
and eax, [0x33333333]
and ecx, [ecx * 2 + 0x33333333]
and ecx, [ecx * 2 + esi + 0x33333333]

;call rel32 0xE8 cd Note: treat cd as id
label_call:
call label_call
call edx
call dword [ 0x33333333 ]
call dword [ eax ]
call dword [ byte eax + 0x33 ]
call dword [ dword eax + 0x33333333 ]
call dword [ eax*4 ]
call dword [ dword eax + eax*4 +  0x33333333 ]
call dword [ byte eax + eax*8 +  0x33 ]

nop

add [edi * 4], esp
add dword [esp],0x12345678
add dword [ebp+0x0],0x12345678
add edi,[edi+edi*8+0x0]
add dword [eax+0x33333333],0x12345678
add dword [eax*4+0x33333333],0x12345678
add dword [eax+eax+0x33333333],0x12345678

