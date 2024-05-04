# Modified from starter code created by/at
# Author: Bram Lewis
# Availability: https://canvas.oregonstate.edu/courses/1957923/assignments/9654612?module_item_id=24358446

import os
import socket
import struct
import threading
import time
import zlib
import random
import string
import requests
import ntplib
import dns.resolver
import dns.exception
from socket import gaierror
from time import ctime
from typing import Tuple, Optional, Any

import select

from timestamp_print import timestamped_print


def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet.

    The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.

    Args:
    data (bytes): The data for which the checksum is to be calculated.

    Returns:
    int: The calculated checksum.
    """

    s: int = 0  # Initialize the sum to 0.

    # Iterate over the data in 16-bit (2-byte) chunks.
    for i in range(0, len(data), 2):
        # Combine two adjacent bytes (8-bits each) into one 16-bit word.
        # data[i] is the high byte, shifted left by 8 bits.
        # data[i + 1] is the low byte, added to the high byte.
        # This forms one 16-bit word for each pair of bytes.
        w: int = (data[i] << 8) + (data[i + 1])
        s += w  # Add the 16-bit word to the sum.

    # Add the overflow back into the sum.
    # If the sum is larger than 16 bits, the overflow will be in the higher bits.
    # (s >> 16) extracts the overflow by shifting right by 16 bits.
    # (s & 0xffff) keeps only the lower 16 bits of the sum.
    # The two parts are then added together.
    s = (s >> 16) + (s & 0xffff)

    # Complement the result.
    # ~s performs a bitwise complement (inverting all the bits).
    # & 0xffff ensures the result is a 16-bit value by masking the higher bits.
    s = ~s & 0xffff

    return s  # Return the calculated checksum.


def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, sequence_number: int = 1, data_size: int = 192) -> bytes:
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    Args:
    icmp_type (int): The type of the ICMP packet. Default is 8 (Echo Request).
    icmp_code (int): The code of the ICMP packet. Default is 0.
    sequence_number (int): The sequence number of the ICMP packet. Default is 1.
    data_size (int): The size of the data payload in the ICMP packet. Default is 192 bytes.

    Returns:
    bytes: A bytes object representing the complete ICMP packet.

    Description:
    The function generates a unique ICMP packet by combining the specified ICMP type, code, and sequence number
    with a data payload of a specified size. It calculates a checksum for the packet and ensures that the packet
    is in the correct format for network transmission.
    """

    # Get the current thread identifier and process identifier.
    # These are used to create a unique ICMP identifier.
    thread_id = threading.get_ident()
    process_id = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    # The & 0xffff ensures the result is within the range of an unsigned 16-bit integer (0-65535).
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Pack the ICMP header fields into a bytes object.
    # 'bbHHh' is the format string for struct.pack, which means:
    # b - signed char (1 byte) for ICMP type
    # b - signed char (1 byte) for ICMP code
    # H - unsigned short (2 bytes) for checksum, initially set to 0
    # H - unsigned short (2 bytes) for ICMP identifier
    # h - short (2 bytes) for sequence number
    header: bytes = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create the data payload for the ICMP packet.
    # It's a sequence of a single randomly chosen alphanumeric character (uppercase or lowercase),
    # repeated to match the total length specified by data_size.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    chksum: int = calculate_icmp_checksum(header + data)

    # Repack the header with the correct checksum.
    # socket.htons ensures the checksum is in network byte order.
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(chksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data


def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1) -> Tuple[Any, float] | Tuple[Any, str]:
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    This function creates a raw socket to send an ICMP Echo Request packet to the given host.
    It then waits for an Echo Reply, measuring the time taken for the round trip. If the
    specified timeout is exceeded before receiving a reply, the function returns None for the ping time.

    Args:
    host (str): The IP address or hostname of the target host.
    ttl (int): Time-To-Live for the ICMP packet. Determines how many hops (routers) the packet can pass through.
    timeout (int): The time in seconds that the function will wait for a reply before giving up.
    sequence_number (int): The sequence number for the ICMP packet. Useful for matching requests with replies.

    Returns:
    Tuple[Any, float] | Tuple[Any, None]: A tuple containing the address of the replier and the total ping time in milliseconds.
    If the request times out, the function returns None for the ping time. The address part of the tuple is also None if no reply is received.
    """

    # Create a raw socket with the Internet Protocol (IPv4) and ICMP.
    # socket.AF_INET specifies the IPv4 address family.
    # socket.SOCK_RAW allows sending raw packets (including ICMP).
    # socket.IPPROTO_ICMP specifies the ICMP protocol.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blocking operations (e.g., recvfrom).
        sock.settimeout(timeout)

        # Create an ICMP Echo Request packet.
        # icmp_type=8 and icmp_code=0 are standard for Echo Request.
        # sequence_number is used to match Echo Requests with Replies.
        packet: bytes = create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        # Send the ICMP packet to the target host.
        # The second argument of sendto is a tuple (host, port).
        # For raw sockets, the port number is irrelevant, hence set to 1.
        try:
            sock.sendto(packet, (host, 1))
        except gaierror:
            return None, None

        # Record the current time to measure the round-trip time later.
        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            # This will be the ICMP Echo Reply if the target host is reachable.
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time = (end - start) * 1000
            total_ping_time = total_ping_time // 1

            # Return the address of the replier and the total ping time.
            return addr[0], str(total_ping_time) + " ms"
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None


def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False) -> str:
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    Args:
    host (str): The IP address or hostname of the target host.
    max_hops (int): Maximum number of hops to try before stopping.
    pings_per_hop (int): Number of pings to perform at each hop.
    verbose (bool): If True, print additional details during execution.

    Returns:
    str: The results of the traceroute, including statistics for each hop.
    """
    # Header row for the results. Each column is formatted for alignment and width.
    results = [f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8}   {'Avg (ms)':>8}   {'Max (ms)':>8}   {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops.
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for the current TTL.
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL.
        for _ in range(pings_per_hop):
            # Ping the host with the current TTL and sequence number.
            # The sequence number is incremented with TTL for each ping.
            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            # If a response is received (not None), append it to ping_times.
            if response is not None:
                ping_times.append(response)

        # If there are valid ping responses, calculate and format the statistics.

        # change formatting back to floats (from the changed return for the ping function)
        for i in range(len(ping_times)):
            ping_times[i] = float(ping_times[i][:-3])

        if ping_times:
            min_time = min(ping_times)  # Minimum ping time.
            avg_time = sum(ping_times) / len(ping_times)  # Average ping time.
            max_time = max(ping_times)  # Maximum ping time.
            count = len(ping_times)  # Count of successful pings.

            # Append the formatted results for this TTL to the results list.
            results.append(f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.0f}ms {avg_time:>8.0f}ms {max_time:>8.0f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(f"{ttl:>3} {'*':<15} {'*':>8}   {'*':>8}   {'*':>8}   {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute.
        if addr and addr[0] == host:
            break

    # Join all results into a single string with newline separators and return.
    return '\n'.join(results)


def check_server_http(url: str) -> Tuple[bool, Optional[int]]:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    and the HTTP status code returned by the server.

    :param url: URL of the server (including http://)
    :return: Tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # The HTTP status code is a number that indicates the outcome of the request.
        # Here, we consider status codes less than 400 as successful,
        # meaning the server is up and reachable.
        # Common successful status codes are 200 (OK), 301 (Moved Permanently), etc.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code)
        # True if the server is up, False if an exception occurs (see except block)
        return is_up, response.status_code

    except requests.RequestException:
        # This block catches any exception that might occur during the request.
        # This includes network problems, invalid URL, etc.
        # If an exception occurs, we assume the server is down.
        # Returning False for the status, and None for the status code,
        # as we couldn't successfully connect to the server to get a status code.
        return False, None


def check_server_https(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL with HTTPS.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a descriptive message.

    :param url: URL of the server (including https://)
    :param timeout: Timeout for the request in seconds. Default is 5 seconds.
    :return: Tuple (True/False for server status, status code, description)
    """
    try:
        # Setting custom headers for the request. Here, 'User-Agent' is set to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        # The timeout ensures that the request does not hang indefinitely.
        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        # Checking if the status code is less than 400. Status codes in the 200-399 range generally indicate success.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    except requests.ConnectionError:
        # This exception is raised for network-related errors, like DNS failure or refused connection.
        return False, None, "Connection error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # A catch-all exception for any error not covered by the specific exceptions above.
        # 'e' contains the details of the exception.
        return False, None, f"Error during request: {e}"


def check_ntp_server(server: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None


def check_dns_server_status(server, query, record_type) -> (bool, str):
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    try:
        # Set the DNS resolver to use the specified server
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)


def check_tcp_port(ip_address: str, port: int) -> (bool, str):
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            return True, f"Port {port} on {ip_address} is open."

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
        return False, f"Port {port} on {ip_address} timed out."

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        return False, f"Port {port} on {ip_address} is closed or not reachable."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"


def check_udp_port(ip_address: str, port: int, timeout: int = 3) -> (bool, str, str):
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. Default is 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                response, server = s.recvfrom(1024)

                if response.decode() == "Destination Unreachable":
                    return False, f"Port {port} on {ip_address} is closed.", f"Response: {response.decode()}"
                else:
                    return True, f"Port {port} on {ip_address} is open", f"Response: {response.decode()}"

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                return True, f"Port {port} on {ip_address} is open or no response received.", "Response: timeout"

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}", "Response: error"


def ping_worker(stop_event, message, client_sock) -> None:
    """
    Ping service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            ping_response = ping(message[2], int(message[3]), int(message[4]), int(message[5]))
            timestamped_print(ping_response)

            # build response string and send back to client thread
            response = "Ping @ " + "serviceID " + message[1] + " " + ping_response[0] + " " + ping_response[1]
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[6]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def traceroute_worker(stop_event, message, client_sock) -> None:
    """
    Traceroute service worker that accepts various service parameters from the Thread call to it; will be called for
    every host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            timestamped_print("Traceroute placeholder")

            response = "Traceroute @ " + "serviceID " + message[1] + " " + "traceroute placeholder - will correct"
            client_sock.send(response.encode())

            time.sleep(int(message[6]))
        # TODO
        # FIGURE OUT WHAT TO FIX THIS WITH
        # while not stop_event.is_set():
        #     # make service call
        #     ping_response = traceroute(message[2], int(message[3]), int(message[4]), bool(message[5]))
        #     timestamped_print(ping_response)
        #
        #     # build response string and send back to client thread
        #     response = "Traceroute @ " + "serviceID " + message[1] + " " + ping_response[0] + " " + ping_response[1]
        #     client_sock.send(response.encode())
        #
        #     # sleep on configured interval
        #     time.sleep(int(message[6]))
        # timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def http_worker(stop_event, message, client_sock) -> None:
    """
    HTTP service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            http_response = check_server_http(message[2])
            timestamped_print(http_response)

            # build response string and send back to client thread
            response = "HTTP @ " + "serviceID " + message[1] + " " + str(http_response[0]) + " " + str(http_response[1])
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[3]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def https_worker(stop_event, message, client_sock) -> None:
    """
    HTTPS service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            https_response = check_server_https(message[2], int(message[3]))
            timestamped_print(https_response)

            # build response string and send back to client thread
            response = "HTTPS @ " + "serviceID " + message[1] + " " + str(https_response[0]) + " " + \
                       str(https_response[1]) + " " + https_response[2]
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[4]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def ntp_worker(stop_event, message, client_sock) -> None:
    """
    NTP service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            ntp_response = check_ntp_server(message[2])
            timestamped_print(ntp_response)

            # build response string and send back to client thread
            response = "NTP @ " + "serviceID " + message[1] + " " + str(ntp_response[0]) + " " + str(ntp_response[1])
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[3]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def dns_worker(stop_event, message, client_sock) -> None:
    """
    DNS service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            dns_response = check_dns_server_status(message[2], message[3], message[4])
            timestamped_print(dns_response)

            # build response string and send back to client thread
            response = "DNS @ " + "serviceID " + message[1] + " " + str(dns_response[0]) + " " + \
                       str(dns_response[1])
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[5]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def tcp_worker(stop_event, message, client_sock) -> None:
    """
    TCP service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            tcp_response = check_tcp_port(message[2], int(message[3]))
            timestamped_print(tcp_response)

            # build response string and send back to client thread
            response = "TCP @ " + "serviceID " + message[1] + " " + str(tcp_response[0]) + " " + \
                       str(tcp_response[1])
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[4]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def udp_worker(stop_event, message, client_sock) -> None:
    """
    UDP service worker that accepts various service parameters from the Thread call to it; will be called for every
    host in the parameter host list; runs until the stop event is set by keyboard interruption; returns None
    """
    try:
        while not stop_event.is_set():
            # make service call
            udp_response = check_udp_port(message[2], int(message[3]), int(message[4]))
            timestamped_print(udp_response)

            # build response string and send back to client thread
            response = "UDP @ " + "serviceID " + message[1] + " " + str(udp_response[0]) + " " + \
                       str(udp_response[1]) + " " + str(udp_response[2])
            client_sock.send(response.encode())

            # sleep on configured interval
            time.sleep(int(message[5]))
        timestamped_print(f'Thread serviceID {message[1]} closed.')

    except Exception as e:
        print("Error:", e)
        timestamped_print("Thread closed.")


def tcp_server():
    # Create socket
    # socket(): create TCP/IP socket using AF_INET for IPv4 and STREAMing socket for TCP
    serv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind socket to an IP address and port
    # bind(): Bind the socket to a specific IP address and port
    serv_address = '127.0.0.1'  # localhost
    serv_port = 5000            # port to listen
    serv_socket.bind((serv_address, serv_port))

    # Listen for incoming requests
    # listen(): Put the socket into server mode and listen for incoming connections
    serv_socket.listen(5)  # arg is backlog of connections allowed
    timestamped_print("TCP server is listening for incoming connections...")    # status message for start of listening

    stop_events = []

    try:
        while True:
            # Accept connections
            # accept(): Accept a new connection
            client_sock, client_address = serv_socket.accept()  # store the socket obj, address in tuple

            # Recv data
            # recv(): Receive data from the client
            msg = client_sock.recv(1024)
            msg = msg.decode().strip().split(' ')  # get list of parameters
            if msg[0] == 'stop':
                for obj in stop_events:
                    obj.set()
                continue
            timestamped_print(f"Connection from {client_address}, thread serviceID {msg[1]} starting...")

            # get service type to start correct worker
            service_type = msg[0]
            match service_type:
                case "Ping":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=ping_worker, args=(stop_event,),
                                                     kwargs={'message': msg, 'client_sock': client_sock})
                case "Traceroute":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=traceroute_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
                case "HTTP":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=http_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
                case "HTTPS":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=https_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
                case "NTP":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=ntp_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
                case "DNS":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=dns_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
                case "TCP":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=tcp_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
                case "UDP":
                    stop_event = threading.Event()
                    stop_events.append(stop_event)
                    client_thread = threading.Thread(target=udp_worker, args=(stop_event,),
                                                     kwargs={'message': msg, "client_sock": client_sock})
            client_thread.start()

    except KeyboardInterrupt:
        stop_event.set()
        timestamped_print("Server is shutting down...")

    finally:
        # Close server socket:
        # close() (on the server socket obj): Close server socket
        serv_socket.close()
        timestamped_print("Server socket closed. Server shut down.")


# if __name__ == "__main___":
tcp_server()