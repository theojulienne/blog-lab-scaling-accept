import sys
import socket
import time
import select
import errno

if len(sys.argv) != 3:
    print('Usage: {} <ip:port> <number of connections>'.format(sys.argv[0]))
    sys.exit(1)

ip, port = sys.argv[1].split(':')
port = int(port)
num_connections = int(sys.argv[2])

conns = []

for i in range(num_connections):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(0)
    err = s.connect_ex((ip, port))
    if errno.errorcode[err] != 'EINPROGRESS':
        print('{}: {}'.format(i, errno.errorcode[err]))

    conns.append(s)

print('Waiting, Ctrl+C to exit.')
while True:
    # just leave these connections until the user kills the script
    _, _, in_error = select.select([], [], conns)
    for errsock in in_error:
        print(errsock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR))
