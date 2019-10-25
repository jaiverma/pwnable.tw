import struct

data = bytes()
with open('opts.bin', 'rb') as f:
    data = f.read()

cnt = 0xc
sz = 0x8
'''
struct sock_filter {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};
'''

for i in range(0, len(data), sz):
    code = struct.unpack('<H', data[i:i+2])[0]
    jt = struct.unpack('<B', data[i+2:i+2+1])[0]
    jf = struct.unpack('<B', data[i+2+1:i+2+1+1])[0]
    k = struct.unpack('<I', data[i+2+1+1:i+2+1+1+4])[0]
    print({
        'code': hex(code),
        'jt': hex(jt),
        'jf': hex(jf),
        'k': hex(k),
    })
