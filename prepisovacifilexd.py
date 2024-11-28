import socket
import threading
import argparse
import struct
import time
import queue
import crc16
import os

# Global message queue for communication between threads
msg_queue = queue.Queue()

# Argument parser for command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--source", type=str)
parser.add_argument("--destination", type=str)
parser.add_argument("--src_port", type=int)
parser.add_argument("--dest_port", type=int)
args = parser.parse_args()

# Local and remote address/port configuration
LOCAL_IP = args.source
LOCAL_PORT = args.src_port
REMOTE_IP = args.destination
REMOTE_PORT = args.dest_port

# UDP socket creation (IPv4, Datagram)
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.settimeout(3)  # Set timeout for handshake
udp_socket.bind((LOCAL_IP, LOCAL_PORT))

# Function to create a message header
def create_header(msg_type: int, flags: int, length: int, msg_id: int, total_fragments: int, current_fragment: int, data: bytes) -> bytes:
    # Validate input parameters
    if msg_type < 0 or msg_type > 255:
        raise ValueError(f"msg_type out of range: {msg_type}")
    if msg_id < 0 or msg_id > 255:
        raise ValueError(f"msg_id out of range: {msg_id}")
    if total_fragments < 0 or total_fragments > 65535:
        raise ValueError(f"total_fragments out of range: {total_fragments}")
    if current_fragment < 0 or current_fragment > 65535:
        raise ValueError(f"current_fragment out of range: {current_fragment}")

    # Global error flag to introduce artificial corruption
    global errored

    # Construct the first byte by combining message type and flags
    first_byte = (msg_type << 4) | flags
    header_format = "!B H B H H H"

    # Add erroneous data if the error flag is set
    if errored:
        data = data + bytes("random text".encode("utf-8"))

    # Calculate CRC for the data
    crc = crc16.crc16xmodem(data)
    # Pack all fields into a header structure
    return struct.pack(header_format, first_byte, length, msg_id, total_fragments, current_fragment, crc)

# Function to parse a message header
def parse_header(header: bytes):
    # Define the format of the header
    header_format = "!B H B H H H"
    unpacked = struct.unpack(header_format, header)

    # Extract message type and flags from the first byte
    first_byte = unpacked[0]
    msg_type = (first_byte >> 4) & 0xF
    flags = first_byte & 0xF

    # Return header fields as a dictionary
    return {
        "msg_type": msg_type,
        "flags": flags,
        "length": unpacked[1],
        "msg_id": unpacked[2],
        "total_fragments": unpacked[3],
        "current_fragment": unpacked[4],
        "crc": unpacked[5]
    }

# Function to perform a handshake for connection establishment
def handshake():
    print("[handshake] Connecting ...")
    syn_received = False

    while True:
        try:
            # Attempt to receive SYN/SYN-ACK/ACK
            data, address = udp_socket.recvfrom(1024)  # Default buffer size
            header = data[:10]
            header_info = parse_header(header)
            msg_type = header_info["msg_type"]

            # Handle SYN message
            if msg_type == 1 and not syn_received:
                print("[Handshake] SYN received")
                syn_received = True
                header = create_header(2, 0, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print("[Handshake] SYN-ACK sent")
                continue

            # Handle SYN-ACK message
            elif msg_type == 2 and not syn_received:
                print("[Handshake] SYN-ACK received")
                header = create_header(3, 0, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print("[Handshake] ACK sent")
                return True

            # Handle ACK message
            elif msg_type == 3 and syn_received:
                print("[Handshake] ACK received")
                return True

        except socket.timeout:
            # If timeout occurs, retry by sending SYN
            header = create_header(1, 0, 0, 0, 1, 1, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            print("[Handshake] SYN sent")
            syn_received = False
            continue

        # Handshake failed
        return False

# Function to close the connection using a 3-way handshake
def three_way_close_handshake():
    global end_connection
    print("[Close] Initiating 3-way close handshake...")

    # Step 1: Send FIN message
    msg_type = 12  # FIN message type
    header = create_header(msg_type, 0, 0, msg_id, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
    print("[Close] FIN sent")

    # Wait for FIN-ACK
    while True:
        try:
            data, _ = udp_socket.recvfrom(1024)
            header_info = parse_header(data[:10])
            if header_info["msg_type"] == 14:  # FIN-ACK
                print("[Close] FIN-ACK received")
                break
        except socket.timeout:
            print("[Close] Resending FIN...")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))

    # Step 2: Send ACK to complete handshake
    msg_type = 3  # ACK message type
    header = create_header(msg_type, 0, 0, msg_id, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
    print("[Close] ACK sent")

    # Mark connection as closed
    end_connection = True
    print("[Close] Connection closed successfully")

# Function to maintain a keep-alive heartbeat between peers
def keep_alive():
    global role, end_connection
    missed_heartbeats = 0

    if role == 1:  # Initiator of the heartbeat
        while not end_connection:
            # Send a heartbeat message
            header = create_header(5, 0, 0, 0, 1, 1, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            time.sleep(2)

            # Check for acknowledgment
            response_received = False
            for _ in range(3):
                time.sleep(1)
                if not msg_queue.empty():
                    msg_queue.get()
                    response_received = True
                    missed_heartbeats = 0
                    break

            if not response_received:
                missed_heartbeats += 1
                print(f"[Keep-alive] Missed heartbeat {missed_heartbeats}")

            if missed_heartbeats >= 3:
                print("[Keep-alive] Connection lost")
                end_connection = True
                break

    else:  # Listener for heartbeat
        while not end_connection:
            time.sleep(5)
            if not msg_queue.empty():
                msg_queue.get()
                missed_heartbeats = 0
                header = create_header(5, 0, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            else:
                missed_heartbeats += 1
                print(f"[Keep-alive] Missed heartbeat {missed_heartbeats}")

            if missed_heartbeats >= 3:
                print("[Keep-alive] Connection lost")
                end_connection = True
                break

# Function to receive messages
def receive():
    global msg_queue, errored, end_connection

    while not end_connection:
        try:
            # Attempt to receive a message
            data, _ = udp_socket.recvfrom(1024)
            header = data[:10]
            payload = data[10:]

            # Parse the received header
            header_info = parse_header(header)
            msg_type = header_info["msg_type"]

            # Handle various message types
            if msg_type == 5:  # Heartbeat message
                print("[Receive] Heartbeat received")
                msg_queue.put(header_info)

            elif msg_type == 7:  # Data message
                print("[Receive] Data message received")
                # Validate CRC and process the message
                computed_crc = crc16.crc16xmodem(payload)
                if computed_crc != header_info["crc"]:
                    print("[Receive] CRC mismatch. Message discarded.")
                else:
                    # Echo acknowledgment for the received message
                    ack_header = create_header(3, 0, 0, header_info["msg_id"], 1, 1, b"")
                    udp_socket.sendto(ack_header, (REMOTE_IP, REMOTE_PORT))
                    print(f"[Receive] Acknowledgment sent for Message ID {header_info['msg_id']}")

            elif msg_type == 12:  # FIN message
                print("[Receive] FIN received, initiating close handshake")
                # Send FIN-ACK
                fin_ack_header = create_header(14, 0, 0, header_info["msg_id"], 1, 1, b"")
                udp_socket.sendto(fin_ack_header, (REMOTE_IP, REMOTE_PORT))
                print("[Receive] FIN-ACK sent")
                end_connection = True

            elif msg_type == 14:  # FIN-ACK message
                print("[Receive] FIN-ACK received")
                end_connection = True

        except socket.timeout:
            # If no message is received within the timeout period, continue listening
            continue

# Function to send data
def send_file(file_path: str):
    global end_connection, msg_queue, errored

    if not os.path.exists(file_path):
        print("[Send] File does not exist")
        return

    # Read the file contents
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Fragment the file into chunks of 512 bytes
    fragment_size = 512
    total_fragments = (len(file_data) + fragment_size - 1) // fragment_size

    for i in range(total_fragments):
        if end_connection:
            print("[Send] Connection ended prematurely")
            break

        # Get the current fragment
        start_index = i * fragment_size
        end_index = min((i + 1) * fragment_size, len(file_data))
        fragment = file_data[start_index:end_index]

        # Create a data message with the current fragment
        msg_type = 7  # Data message type
        msg_id = i + 1
        header = create_header(msg_type, 0, len(fragment), msg_id, total_fragments, i + 1, fragment)
        udp_socket.sendto(header + fragment, (REMOTE_IP, REMOTE_PORT))

        # Wait for acknowledgment of the fragment
        ack_received = False
        for _ in range(3):  # Retry up to 3 times
            try:
                data, _ = udp_socket.recvfrom(1024)
                header_info = parse_header(data[:10])
                if header_info["msg_type"] == 3 and header_info["msg_id"] == msg_id:  # ACK received
                    print(f"[Send] ACK received for fragment {msg_id}")
                    ack_received = True
                    break
            except socket.timeout:
                print(f"[Send] Resending fragment {msg_id}")
                udp_socket.sendto(header + fragment, (REMOTE_IP, REMOTE_PORT))

        if not ack_received:
            print(f"[Send] Failed to receive ACK for fragment {msg_id}. Aborting.")
            end_connection = True
            break

    if not end_connection:
        print("[Send] File sent successfully")

# Main function to start the program
def main():
    global end_connection, role

    print("[Main] Starting...")

    # Perform handshake to establish the connection
    if handshake():
        print("[Main] Handshake completed successfully")
    else:
        print("[Main] Handshake failed")
        return

    # Start threads for sending and receiving
    receive_thread = threading.Thread(target=receive, daemon=True)
    receive_thread.start()

    if role == 1:  # Role 1 (Sender)
        send_thread = threading.Thread(target=send_file, args=("example_file.txt",), daemon=True)
        send_thread.start()

    # Start keep-alive heartbeat
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)
    keep_alive_thread.start()

    # Wait for all threads to complete
    receive_thread.join()
    if role == 1:
        send_thread.join()
    keep_alive_thread.join()

    # Close the connection
    if not end_connection:
        three_way_close_handshake()

    print("[Main] Program finished")

# Entry point
if __name__ == "__main__":
    try:
        role = int(input("Enter role (1 for sender, 2 for receiver): "))
        if role not in [1, 2]:
            raise ValueError("Invalid role. Enter 1 or 2.")
        errored = False  # Global error injection flag
        end_connection = False  # Global connection termination flag
        main()
    except Exception as e:
        print(f"[Error] {e}")
    finally:
        udp_socket.close()
        print("[Main] Socket closed")
