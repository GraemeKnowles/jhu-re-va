[BITS 32]

add eax, 0x12345678
add eax, 0x12345678
add ecx, [ 0x33333333 ]
add edx, ecx
add ebx, [ ecx + 0x33 ]
add esp, [ ecx + 0x33333333 ]
add ebp, [ ecx*1 + 0x33333333 ]
add esi, [ ecx*2 + 0x33333333 ]
add edi, [ ecx*4 + 0x33333333 ]
add eax, [ ecx*8 + 0x33333333 ]
add ecx, [ ecx*1 + esi + 0x33333333 ]
add edx, [ ecx*2 + esi + 0x33333333 ]
add ebx, [ ecx*4 + esi + 0x33333333 ]
add esp, [ ecx*8 + esi + 0x33333333 ]
add ecx, esi
add [ dword 0x33333333 ], 0x12345678
add [ 0x33333333 ], esi
add [ ecx ], 0x12345678
add [ ecx + 0x33 ], 0x12345678
add [ ecx + 0x33333333 ], 0x12345678
add [ ecx*1 + 0x33333333 ], 0x12345678
add [ ecx*2 + 0x33333333 ], 0x12345678
add [ ecx*4 + 0x33333333 ], 0x12345678
add [ ecx*8 + 0x33333333 ], 0x12345678
add [ ecx*1 + esi + 0x33333333 ], 0x12345678
add [ ecx*2 + esi + 0x33333333 ], 0x12345678
add [ ecx*4 + esi + 0x33333333 ], 0x12345678
add [ ecx*8 + esi + 0x33333333 ], 0x12345678
add [ ecx + 0x33 ], esi
add [ ecx + 0x33333333 ], esi
add [ ecx*1 + 0x33333333 ], esi
add [ ecx*2 + 0x33333333 ], esi
add [ ecx*4 + 0x33333333 ], esi
add [ ecx*8 + 0x33333333 ], esi
add [ ecx*1 + esi + 0x33333333 ], esi
add [ ecx*2 + esi + 0x33333333 ], esi
add [ ecx*4 + esi + 0x33333333 ], esi
add [ ecx*8 + esi + 0x33333333 ], esi