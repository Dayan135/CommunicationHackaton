import socket
import struct
import threading
from scapy.all import *
from scapy.layers.inet import UDP, IP
import time

MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
PAYLOAD_TYPE = 0x4
BUFFER_SIZE = 1024

# Function to listen for broadcast messages
def is_valid_broadcast(packet):
    try:
        if UDP in packet and Raw in packet:
            data = packet[Raw].load
            magic_cookie, message_type, udp_port, tcp_port = struct.unpack("!I B H H", data)
            if magic_cookie == MAGIC_COOKIE and message_type == MESSAGE_TYPE_OFFER:
                return packet[IP].src, udp_port, tcp_port
    except Exception as e:
        return None
    return None

def sniff_broadcast_packets(timeout=10):
    print("Sniffing for broadcast packets...")
    detected_info = {}

    def process_packet(packet):
        nonlocal detected_info
        result = is_valid_broadcast(packet)
        if result:
            ip, udp_port, tcp_port = result
            print(f"Received offer from {ip} (UDP Port={udp_port}, TCP Port={tcp_port})")
            detected_info = {"ip": ip, "udp_port": udp_port, "tcp_port": tcp_port}
            return True

    def stop_sniff(packet):
        return bool(is_valid_broadcast(packet))

    sniff(filter="udp", prn=process_packet, stop_filter=stop_sniff, timeout=timeout)
    return detected_info if detected_info else None

# Updated TCP Handler
def handle_tcp_connection(server_ip, tcp_port, connection_id, file_size):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.connect((server_ip, tcp_port))
            print(f"[TCP {connection_id}] Connected to {server_ip}:{tcp_port}")

            tcp_socket.sendall(f"{file_size}\n".encode())

            start_time = time.time()
            received_bytes = 0
            while received_bytes < file_size:
                data = tcp_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                received_bytes += len(data)
            end_time = time.time()

            duration = end_time - start_time
            speed = received_bytes * 8 / duration / 1e6
            print(f"[TCP {connection_id}] Transfer complete: {received_bytes} bytes in {duration:.2f}s ({speed:.2f} Mbps)")
    except Exception as e:
        print(f"[TCP {connection_id}] Error: {e}")

# Updated UDP Handler
def handle_udp_connection(server_ip, udp_port, connection_id, file_size):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.settimeout(2)

            request_packet = struct.pack("!IbQ", MAGIC_COOKIE, MESSAGE_TYPE_REQUEST, file_size)
            udp_socket.sendto(request_packet, (server_ip, udp_port))

            print(f"[UDP {connection_id}] Request sent to {server_ip}:{udp_port}")

            received_segments = set()
            start_time = time.time()
            while True:
                try:
                    data, _ = udp_socket.recvfrom(BUFFER_SIZE + 21)
                    if len(data) >= 21:
                        cookie, msg_type, total_segments, segment_num = struct.unpack("!IbQQ", data[:21])
                        if cookie == MAGIC_COOKIE and msg_type == PAYLOAD_TYPE:
                            received_segments.add(segment_num)
                except socket.timeout:
                    break

            end_time = time.time()
            duration = end_time - start_time
            total_segments_expected = total_segments
            packets_received = len(received_segments)
            packet_loss = (1-(packets_received / total_segments_expected))*100
            speed = (packets_received * BUFFER_SIZE * 8) /  duration / 1e6

            print(f"[UDP {connection_id}] Transfer complete: {packets_received}/{total_segments_expected} packets in {duration:.2f}s, Loss: {packet_loss:.2f}%, Speed: {speed:.2f} Mbps")
    except Exception as e:
        print(f"[UDP {connection_id}] Error: {e}")

# Main client function
def main():
    file_size = int(input("Enter the file size (in bytes): "))
    num_tcp_connections = int(input("Enter the number of TCP connections: "))
    num_udp_connections = int(input("Enter the number of UDP connections: "))

    while True:
        info = sniff_broadcast_packets()
        if info is None:
            continue
        ip = info["ip"]
        udp_port = info["udp_port"]
        tcp_port = info["tcp_port"]

        print(f"Connecting to server at {ip} (TCP port: {tcp_port}, UDP port: {udp_port})")

        tcp_threads = []
        for i in range(num_tcp_connections):
            thread = threading.Thread(target=handle_tcp_connection, args=(ip, tcp_port, i + 1, file_size))
            thread.start()
            tcp_threads.append(thread)

        udp_threads = []
        for i in range(num_udp_connections):
            thread = threading.Thread(target=handle_udp_connection, args=(ip, udp_port, i + 1, file_size))
            thread.start()
            udp_threads.append(thread)

        for thread in tcp_threads + udp_threads:
            thread.join()

        print("All transfers complete. Listening for new offers...")

if __name__ == "__main__":
    main()
