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
    Sniffs the network for broadcast packets and stops once a valid packet is detected.
    Returns the IP, UDP port, and TCP port of the sender.
    """
    print("Sniffing for broadcast packets...")

    detected_info = {}

    def process_packet(packet):
        nonlocal detected_info
        result = is_valid_broadcast(packet)
        if result:
            ip, udp_port, tcp_port = result
            print(f"Received broadcast: IP={ip}, UDP Port={udp_port}, TCP Port={tcp_port}")
            detected_info = {"ip": ip, "udp_port": udp_port, "tcp_port": tcp_port}
            return True  # Indicate the packet is valid and should stop sniffing

    # Define a custom stop function to terminate sniffing on a valid packet
    def stop_sniff(packet):
        return bool(is_valid_broadcast(packet))  # Stop sniffing if a valid packet is found

    # Sniff UDP packets on the network and stop when a valid packet is found
    sniff(filter="udp", prn=process_packet, stop_filter=stop_sniff, timeout=timeout)

    return detected_info if detected_info else None


# Function to handle a single TCP connection

def handle_tcp_connection(server_ip, tcp_port, connection_id, file_size):
    """
    Handles a single TCP connection to the server.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.connect((server_ip, tcp_port))
            print(f"TCP connection {connection_id} established with {server_ip}:{tcp_port}")

            # Send or receive data as required (placeholder example)
            tcp_socket.sendall(f"Connection {connection_id}: Ready to transfer {file_size} bytes.".encode())
            response = tcp_socket.recv(1024)
            print(f"TCP connection {connection_id} received: {response.decode()}")
    except Exception as e:
        print(f"Error in TCP connection {connection_id}: {e}")

def handle_udp_connection(server_ip, udp_port, connection_id, file_size):
    """
    Handles a single UDP connection to the server.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            print(f"UDP connection {connection_id} established with {server_ip}:{udp_port}")

            # Send or receive data as required (placeholder example)
            message = f"Connection {connection_id}: Ready to transfer {file_size} bytes."
            udp_socket.sendto(message.encode(), (server_ip, udp_port))
            data, addr = udp_socket.recvfrom(1024)
            print(f"UDP connection {connection_id} received: {data.decode()} from {addr}")
    except Exception as e:
        print(f"Error in UDP connection {connection_id}: {e}")

# Main client function
def main():
    # Listen for the server's broadcast offer

    # User inputs
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

        # Create threads for TCP connections
        tcp_threads = []
        for i in range(num_tcp_connections):
            thread = threading.Thread(target=handle_tcp_connection, args=(ip, tcp_port, i + 1, file_size))
            thread.start()
            tcp_threads.append(thread)

        # Create threads for UDP connections
        udp_threads = []
        for i in range(num_udp_connections):
            thread = threading.Thread(target=handle_udp_connection, args=(ip, udp_port, i + 1, file_size))
            thread.start()
            udp_threads.append(thread)

        # Wait for all threads to complete
        for thread in tcp_threads + udp_threads:
            thread.join()

        print("All connections completed.")


    # Simulated file data
    # data_chunk = b"x" * file_size
    #
    # # Create threads for TCP connections
    # tcp_threads = []
    # for _ in range(num_tcp_connections):
    #     thread = threading.Thread(target=handle_tcp_connection, args=(server_ip, tcp_port, data_chunk))
    #     tcp_threads.append(thread)
    #     thread.start()
    #
    # # Create threads for UDP connections
    # udp_threads = []
    # for _ in range(num_udp_connections):
    #     thread = threading.Thread(target=handle_udp_connection, args=(server_ip, udp_port, data_chunk))
    #     udp_threads.append(thread)
    #     thread.start()
    #
    # # Wait for all threads to finish
    # for thread in tcp_threads + udp_threads:
    #     thread.join()
    #
    # print("All data sent successfully!")

if __name__ == "__main__":
    main()