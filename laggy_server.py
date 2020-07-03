import time
import socket
import sys

backlog = 10
if len(sys.argv) > 1:
    backlog = int(sys.argv[1])

PORT = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', PORT))
s.listen(backlog)
print('Listening with backlog {}'.format(backlog))

while True:
    print("Accepted: {}".format(s.accept()))
    time.sleep(2)