import socket

HOST = ""  # All available hosts
PORT = 50007
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("Accepted connection:")
    print(conn)
    print("Accepted address:")
    print(addr)
    with conn:
        print("Connected by", addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
