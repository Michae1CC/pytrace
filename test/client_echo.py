# Echo client program
import socket

HOST = "localhost"
PORT = 50007
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Heyo")
    data = s.recv(1024)

print("Recv", repr(data))
