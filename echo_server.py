import socket

server_address = "0.0.0.0"
server_port = 5684
bufsize = 1500  # typical MTU-sized buffer

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((server_address, server_port))

print(f"Listening on {server_address}:{server_port}")

while True:
    data, client_address = sock.recvfrom(bufsize)
    if not data:
        continue
    print(f"received {len(data)} bytes from {client_address}: {data!r}")
    sent = sock.sendto(data, client_address)
    print(f"echoed {sent} bytes back")
