from pwn import *
import base64
import codecs
rot13 = lambda s : codecs.getencoder("rot-13")(s)[0]

r = remote("35.198.78.168", 31150)

ans = b'Insert work proof containing the decoded header:\r\n'
dummy = b'Insert work proof containing the decoded header:\r\n'

while dummy == ans:
    r.recvline()
    line = r.recvline().decode().strip()
    line = rot13(line)
    print(line)
    line = base64.b64decode(line)
    r.sendline(line)
    ans = r.recvline()

print(ans)
r.interactive()