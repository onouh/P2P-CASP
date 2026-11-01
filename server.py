

import socket
from protocol import unpack_message, pack_message, INIT, PEER_LIST

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 5000))

print("Server is waiting for messages...")

while True:
    data, client_address = server.recvfrom(1212)

    try:
        msg_type, seq, peer_id, payload = unpack_message(data)

        print("Received message:")
        print("  Type:", msg_type)
        print("  Sequence:", seq)
        print("  Peer ID:", peer_id)
        print("  Payload:", payload)

        if msg_type == INIT:
            print("Client initialization received!")

            response = pack_message(
                PEER_LIST,
                seq,
                0,
                b"Registration successful"
            )

            server.sendto(response, client_address)

    except ValueError as error:
        print("Invalid packet:", error)
