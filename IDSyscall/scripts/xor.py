import sys

b = str(sys.argv[1])
xor_result = []

for i in range(len(b)):
    xor_result.append(ord(b[i]) ^ 0xaa)

print('{ 0x' + ', 0x'.join(hex(x)[2:] for x in xor_result) + ', 0xaa };')
