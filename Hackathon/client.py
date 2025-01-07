import socket
import struct
import threading

MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2

# Function to listen for broadcast messages
def listen_for_server_offer():
    print("Listening for server offers...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as broadcast_socket:
        broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        broadcast_socket.bind(("0.0.0.0", 0))  # Dynamically assign a listening port

        while True:
            data, addr = broadcast_socket.recvfrom(1024)
            try:
                # Unpack the broadcast message
                magic_cookie, message_type, udp_port, tcp_port = struct.unpack("!I B H H", data)

                # Validate the message
                if magic_cookie == MAGIC_COOKIE and message_type == MESSAGE_TYPE_OFFER:
                    print(f"Offer received from {addr[0]}:")
                    print(f"  Server IP: {addr[0]}")
                    print(f"  UDP Port: {udp_port}")
                    print(f"  TCP Port: {tcp_port}")
                    return addr[0], udp_port, tcp_port
                else:
                    print(f"Invalid broadcast message from {addr[0]}")
            except struct.error:
                print(f"Malformed message from {addr[0]}")

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
    server_ip, udp_port, tcp_port = listen_for_server_offer()

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