rf = open('chall.pdf',mode='rb')
wf = open('solve.pdf',mode='wb')

lines = rf.read().hex()
magic_nums = [0x25, 0x50, 0x44, 0x46, 0x2D]
n = 2
lines  = [lines[i:i+n] for i in range(0, len(lines), n)]

for i, hexy in enumerate(lines):
    char = int("0x"+hexy, 16) ^ (magic_nums[i % len(magic_nums)])
    wf.write(char.to_bytes(1, "big"))
    