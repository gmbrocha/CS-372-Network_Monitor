# Modified from starter code created by/at
# Author: Bram Lewis
# Availability: https://canvas.oregonstate.edu/courses/1957923/assignments/9654612?module_item_id=24358446

import socket
from timestamp_print import timestamped_print


def tcp_server():
    # Create socket
    # socket(): create TCP/IP socket using AF_INET for IPv4 and STREAMing socket for TCP
    serv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind socket to an IP address and port
    # bind(): Bind the socket to a specific IP address and port
    serv_address = '127.0.0.1'  # localhost
    serv_port = 8000           # port to listen
    serv_socket.bind((serv_address, serv_port))

    # Listen for incoming requests
    # listen(): Put the socket into server mode and listen for incoming connections
    serv_socket.listen(5)                                       # arg is backlog of connections allowed
    timestamped_print("TCP server is listening for incoming connections...")    # status message for start of listening

    try:
        while True:
            # Accept connections
            # accept(): Accept a new connection
            client_sock, client_address = serv_socket.accept()  # store the socket obj, address in tuple
            timestamped_print(f"Connection from {client_address}")

            try:
                # Send and Recv data
                # recv(): Receive data from the client
                msg = client_sock.recv(1024)
                timestamped_print(f"Received message: {msg.decode()}")

                # sendall(): Send a response back to the client
                response = "Message received."
                client_sock.sendall(response.encode())

            finally:
                # Close the Client connection:
                # close() (on the client socket obj): Close the connection
                client_sock.close()
                timestamped_print(f"Connection with {client_address} closed.")
    except KeyboardInterrupt:
        timestamped_print("Server is shutting down...")

    finally:
        # Close server socket:
        # close() (on the server socket obj): Close server socket
        serv_socket.close()
        timestamped_print("Server socket closed.")


# if __name__ == "__main___":

tcp_server()
