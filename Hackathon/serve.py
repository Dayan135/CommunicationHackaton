import socket
import threading
import struct
import time
import ipaddress
import netifaces

MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
PAYLOAD_TYPE = 0x4
BUFFER_SIZE = 1024

# Retrieve broadcast address dynamically
def get_broadcast_address():
    interfaces = netifaces.interfaces()
    ret = []
    for interface in interfaces:
        try:
            details = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in details:
                ipv4_info = details[netifaces.AF_INET][0]
                broadcast = ipv4_info['broadcast']
                ret.append(broadcast)
        except KeyError:
            continue
    return ret

# TCP Handler: Send requested file size worth of data
def handle_tcp_client(client_socket):
    with client_socket:
        try:
            print("[TCP] Client connected")
            data = b''
            while not data.endswith(b'\n'):
                data += client_socket.recv(BUFFER_SIZE)
            file_size = int(data.strip())
            print(f"[TCP] Sending {file_size} bytes")
            sent_bytes = 0
            while sent_bytes < file_size:
                chunk_size = min(BUFFER_SIZE, file_size - sent_bytes)
                client_socket.sendall(b'A' * chunk_size)
                sent_bytes += chunk_size
            print("[TCP] File transfer complete")
        except Exception as e:
            print(f"[TCP] Error: {e}")

# UDP Handler: Send segmented packets with sequence numbers
def handle_udp_client(udp_socket, addr, file_size):
    try:
        print(f"[UDP] Handling request from {addr}")
        total_segments = (file_size + BUFFER_SIZE - 1) // BUFFER_SIZE
        for i in range(total_segments):
            payload = struct.pack('!IbQQ', MAGIC_COOKIE, PAYLOAD_TYPE, total_segments, i) + b'A' * BUFFER_SIZE
            udp_socket.sendto(payload, addr)
        print(f"[UDP] Transfer to {addr} complete")
    except Exception as e:
        print(f"[UDP] Error in thread: {e}")

def handle_udp_request(udp_socket):
    print("[UDP] Server started")
    while True:
        data, addr = udp_socket.recvfrom(BUFFER_SIZE)
        try:
            if len(data) >= 13:
                cookie, msg_type, file_size = struct.unpack('!IbQ', data[:13])
                if cookie == MAGIC_COOKIE and msg_type == MESSAGE_TYPE_REQUEST:
                    threading.Thread(target=handle_udp_client, args=(udp_socket, addr, file_size), daemon=True).start()
        except Exception as e:
            print(f"[UDP] Error: {e}")

# Send UDP broadcast offers
def send_udp_broadcast(udp_port, tcp_port, broadcast_port):
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_address = get_broadcast_address()
    while True:
        for address in broadcast_address:
            offer_message = struct.pack("!I B H H", MAGIC_COOKIE, MESSAGE_TYPE_OFFER, udp_port, tcp_port)
            broadcast_socket.sendto(offer_message, (address, broadcast_port))
        print("[UDP] Offer broadcast sent")
        time.sleep(1)

def main():
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(("0.0.0.0", 0))
    tcp_port = tcp_server.getsockname()[1]
    tcp_server.listen(5)
    print(f"[TCP] Listening on port {tcp_port}")

    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("0.0.0.0", 0))
    udp_port = udp_server.getsockname()[1]
    print(f"[UDP] Listening on port {udp_port}")

    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(("0.0.0.0", 0))
    broadcast_port = broadcast_socket.getsockname()[1]
    print(f"[Broadcast] on port {broadcast_port}")

    threading.Thread(target=handle_udp_request, args=(udp_server,), daemon=True).start()
    threading.Thread(target=send_udp_broadcast, args=(udp_port, tcp_port, broadcast_port), daemon=True).start()

    while True:
        client_socket, addr = tcp_server.accept()
        print(f"[TCP] Connection from {addr}")
        threading.Thread(target=handle_tcp_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    main()
