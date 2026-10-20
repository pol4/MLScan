import socket, struct
host = 'postgres.mlscan-data.svc.cluster.local'
print('resolve:', socket.gethostbyname(host))
s = socket.create_connection((host, 5432), timeout=10)
body = struct.pack('!i', 196608) + b'user\x00mlscan\x00database\x00mlscan\x00client_encoding\x00UTF8\x00\x00'
s.sendall(struct.pack('!i', len(body) + 4) + body)
s.settimeout(10)
try:
    d = s.recv(4096)
    print('recv', len(d), d[:32])
except Exception as e:
    print('err', type(e).__name__, e)
