BITS 32 ; BITS directive

section .text ; section directive to indicate executable 'code'

; function that swaps the input arguments on the stack
swapAB:
	xchg eax, [esp+4] ; EAX <-> A (SA now OV, EAX now A)
	xchg eax, [esp+8] ; EAX <-> B (SB now A, EAX now B)
	xchg eax, [esp+4] ; EAX <-> A (SA now B, EAX now OV)
	retn

push 8
push 7
call swapAB
