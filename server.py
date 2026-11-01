
import socket

# Create a UDP socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Listen on localhost, port 5000
server.bind(("127.0.0.1", 5000))

print("Server is waiting for messages...")

while True:
    data, client_address = server.recvfrom(1200)

    message = data.decode()
    print(f"Received from {client_address}: {message}")

    # Respond to the client
    server.sendto(b"Hello from server!", client_address)
