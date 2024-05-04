# Modified from starter code created by/at
# Author: Bram Lewis
# Availability: https://canvas.oregonstate.edu/courses/1957923/assignments/9654612?module_item_id=24358446

import socket
from timestamp_print import timestamped_print


def udp_server():
    # Create a Datagram socket
    # socket(): create UDP socket using AF_INET for IPv4 and SOCK_DGRAM socket for UDP
    serv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind socket to an IP address and port
    # bind(): Bind the socket to a specific IP address and port
    serv_address = '127.0.0.1'  # localhost
    serv_port = 6000  # port to listen
    serv_socket.bind((serv_address, serv_port))

    timestamped_print("UDP server is ready to receive messages...")  # status message for start of listening

    try:
        while True:
            # Recv and respond to data
            # recvfrom(): receive data from clients, capturing the client's address
            message, client_address = serv_socket.recvfrom(1024)
            timestamped_print(f"Received message: {message.decode()} from {client_address}")

            # sendto(): Send a response back to the client's address
            response = "Message Received"
            serv_socket.sendto(response.encode(), client_address)

    except KeyboardInterrupt:
        print("Server is shutting down...")
        # Close socket
        # close()
        serv_socket.close()
        print("Server socket closed.")

    finally:
        return


# if __name__ == "__main__":

udp_server()