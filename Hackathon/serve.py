import socket
import threading
import struct
import time
import ipaddress
import netifaces


MAGIC_COOKIE = 0xabcddcba
MESSAGE_TYPE_OFFER = 0x2

def get_broadcast_address():
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        try:
            # Get network details for each interface
            details = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in details:  # Check for IPv4 configuration
                ipv4_info = details[netifaces.AF_INET][0]
                ip = ipv4_info['addr']
                subnet = ipv4_info['netmask']
                broadcast = ipv4_info['broadcast']
                return broadcast
        except KeyError:
            continue
    return None

# Thread to handle TCP client connection
def handle_tcp_client(client_socket):
    with client_socket:
        print("TCP client connected")
        filename = client_socket.recv(1024).decode()
        with open(filename, "wb") as f:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                f.write(data)
        print(f"File {filename} received")

# Function to handle UDP file reception
def handle_udp_server(server_socket):
    print("UDP server started")
    while True:
        data, addr = server_socket.recvfrom(1024)
        filename, file_data = data.decode().split(":", 1)
        with open(filename, "wb") as f:
            f.write(file_data.encode())
        print(f"File {filename} received from {addr}")

# Function to send UDP broadcast offers
def send_udp_broadcast(udp_port, tcp_port, broadcast_port):
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    magic_cookie = MAGIC_COOKIE
    message_type = MESSAGE_TYPE_OFFER
    broadcast_address = get_broadcast_address()


    while True:
        # Pack the offer message
        offer_message = struct.pack("!I B H H", magic_cookie, message_type, udp_port, tcp_port)
        # Broadcast the message to the dynamically assigned port
        broadcast_socket.sendto(offer_message, (broadcast_address, broadcast_port))
        print("Offer message sent via UDP broadcast")
        time.sleep(1)

# Main server function
def main():
    # Dynamically bind TCP and UDP servers to any available port (port 0)
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(("0.0.0.0", 0))  # Let the OS choose an available port
    tcp_port = tcp_server.getsockname()[1]  # Get the dynamically assigned TCP port
    tcp_server.listen(5)
    print(f"TCP server listening on port {tcp_port}")

    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("0.0.0.0", 0))  # Let the OS choose an available port
    udp_port = udp_server.getsockname()[1]  # Get the dynamically assigned UDP port
    print(f"UDP server listening on port {udp_port}")

    # Dynamically assign a broadcast port
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.bind(("0.0.0.0", 0))  # Let the OS choose a broadcast port
    broadcast_port = broadcast_socket.getsockname()[1] # Get the dynamically assigned UDP broadcast port
    print(f"Broadcasting on port {broadcast_port}")

    # Start UDP server handling in a separate thread
    threading.Thread(target=handle_udp_server, args=(udp_server,), daemon=True).start()

    # Start the UDP broadcast thread
    threading.Thread(target=send_udp_broadcast, args=(udp_port, tcp_port, broadcast_port), daemon=True).start()

    while True:
        client_socket, addr = tcp_server.accept()
        print(f"TCP connection from {addr}")
        threading.Thread(target=handle_tcp_client, args=(client_socket,), daemon=True).start()





if __name__ == "__main__":
    main()