#!/usr/bin/env python3
# Chaperon Request I: raw frames for the unclassifiable-packet checks, sent from the generator VF's kernel
# netdev (AF_PACKET) through the switchdev hairpin to the tenant VF.
#   usage: rawframes.py <dev> <dst_mac> <kind> <count>
#   kind: arp | ipv6 | frag_first | frag_later | bad_version | bad_ihl | ok
import socket, struct, sys
dev, dmac, kind, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
D = bytes.fromhex(dmac.replace(':', '')); S = bytes.fromhex('3cfdfec49338')
SIP, DIP = socket.inet_aton('10.0.0.1'), socket.inet_aton('10.0.0.2')
udp = struct.pack('!HHHH', 1111, 2222, 8 + 16, 0) + b'\xab' * 16
def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16); return (~s) & 0xffff
def ipv4(payload, frag=0, ver=4, ihl=5):
    h = struct.pack('!BBHHHBBH4s4s', (ver << 4) | ihl, 0, 20 + len(payload), 1, frag, 64, 17, 0, SIP, DIP)
    h = h[:10] + struct.pack('!H', csum(h)) + h[12:]
    return h + payload
if kind == 'arp':
    frame = D + S + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + S + SIP + b'\x00' * 6 + DIP
elif kind == 'ipv6':
    frame = D + S + b'\x86\xdd' + struct.pack('!IHBB', 6 << 28, len(udp), 17, 64) + b'\xfd' + b'\x00' * 14 + b'\x01' + b'\xfd' + b'\x00' * 14 + b'\x02' + udp
elif kind == 'frag_first':
    frame = D + S + b'\x08\x00' + ipv4(udp, frag=0x2000)          # MF, offset 0
elif kind == 'frag_later':
    frame = D + S + b'\x08\x00' + ipv4(b'\xab' * 24, frag=0x00b9)  # offset 185*8, last fragment
elif kind == 'bad_version':
    frame = D + S + b'\x08\x00' + ipv4(udp, ver=6)                  # EtherType IPv4, version nibble 6
elif kind == 'bad_ihl':
    frame = D + S + b'\x08\x00' + ipv4(udp, ihl=3)                  # header length 12 < 20
elif kind == 'ok':
    frame = D + S + b'\x08\x00' + ipv4(udp)                         # the armed ALLOW tuple
else:
    sys.exit('unknown kind')
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((dev, 0))
for _ in range(n): s.send(frame)
print('sent', n, kind, len(frame), 'bytes')
