import socket
import struct
import threading
from scapy.all import *
import struct

from scapy.layers.inet import UDP, IP

MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2

# Function to listen for broadcast messages
def is_valid_broadcast(packet):
    """
    Validates if the packet matches the broadcast message format.
    """
    try:
        # Ensure the packet is UDP and has payload
        if UDP in packet and Raw in packet:
            data = packet[Raw].load
            # Unpack and check the broadcast message structure
            magic_cookie, message_type, udp_port, tcp_port = struct.unpack("!I B H H", data)
            if magic_cookie == MAGIC_COOKIE and message_type == MESSAGE_TYPE_OFFER:
                return packet[IP].src, udp_port, tcp_port
    except Exception as e:
        print(f"Error parsing packet: {e}")
    return None

def sniff_broadcast_packets(timeout=10):
    """
    Sniffs the network for broadcast packets matching the server's broadcast format.
    """
    print("Sniffing for broadcast packets...")
    def process_packet(packet):
        result = is_valid_broadcast(packet)
        if result:
            ip, udp_port, tcp_port = result
            print(f"Received broadcast: UDP Port={udp_port}, TCP Port={tcp_port}")

    # Sniff UDP packets on the network
    sniff(filter="udp", prn=process_packet, timeout=timeout)


# Function to handle a single TCP connection
def handle_tcp_connection(server_ip, tcp_port, data_chunk):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((server_ip, tcp_port))
        print(f"TCP connection established with {server_ip}:{tcp_port}")
        client_socket.sendall(data_chunk)
        print("TCP data sent")

# Function to handle a single UDP connection
def handle_udp_connection(server_ip, udp_port, data_chunk):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        print(f"UDP connection established with {server_ip}:{udp_port}")
        client_socket.sendto(data_chunk, (server_ip, udp_port))
        print("UDP data sent")

# Main client function
def main():
    # Listen for the server's broadcast offer
    server_ip, udp_port, tcp_port = sniff_broadcast_packets()

    # User inputs
    file_size = int(input("Enter the file size (in bytes): "))
    num_tcp_connections = int(input("Enter the number of TCP connections: "))
    num_udp_connections = int(input("Enter the number of UDP connections: "))

    # Simulated file data
    data_chunk = b"x" * file_size

    # Create threads for TCP connections
    tcp_threads = []
    for _ in range(num_tcp_connections):
        thread = threading.Thread(target=handle_tcp_connection, args=(server_ip, tcp_port, data_chunk))
        tcp_threads.append(thread)
        thread.start()

    # Create threads for UDP connections
    udp_threads = []
    for _ in range(num_udp_connections):
        thread = threading.Thread(target=handle_udp_connection, args=(server_ip, udp_port, data_chunk))
        udp_threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in tcp_threads + udp_threads:
        thread.join()

    print("All data sent successfully!")

if __name__ == "__main__":
    main()