
import socket

# Create a UDP socket
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ("127.0.0.1", 5000)

# Send message to server
client.sendto(b"INIT", server_address)

print("INIT message sent!")

# Receive server response
data, address = client.recvfrom(1200)

print("Server response:", data.decode())

client.close()
