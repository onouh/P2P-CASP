
import socket
from protocol import pack_message, unpack_message, INIT

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(3)

server_address = ("127.0.0.1", 5000)

message = pack_message(
    msg_type=INIT,
    sequence_num=1,
    peer_id=1
)

client.sendto(message, server_address)

print("Binary INIT message sent!")

try:
    data, address = client.recvfrom(1212)

    msg_type, seq, peer_id, payload = unpack_message(data)

    print("Server response:")
    print("  Message type:", msg_type)
    print("  Sequence:", seq)
    print("  Peer ID:", peer_id)
    print("  Payload:", payload.decode())

except socket.timeout:
    print("Server did not respond")

finally:
    client.close()
