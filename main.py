import socket
import threading
import argparse
import struct
import time
import queue
import os
# import crc16

# Global message queue for communication between threads
msg_queue = queue.Queue()

# Default address to save files
default_directory = os.getcwd()

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


def crc16(data: bytes, poly: int = 0x1021, init_value: int = 0xFFFF) -> int:
    crc = init_value
    for byte in data:
        crc ^= (byte << 8)  # Align the byte with the high byte of CRC
        for _ in range(8):  # Process each bit
            if crc & 0x8000:  # If the highest bit is set
                crc = (crc << 1) ^ poly  # XOR with the polynomial
            else:
                crc = crc << 1  # Just shift left
            crc &= 0xFFFF  # Ensure CRC remains a 16-bit value
    return crc


# Globálne premenné pre správu ID
last_send_id = 0
last_recv_id = 0


# Funkcia pre generovanie ID pre odosielané správy
def generate_send_id():
    global last_send_id
    last_send_id = (last_send_id + 1) % 256
    # print(f"[ID Generation] last_send_id: {last_send_id}")  # Debug print
    return last_send_id


def validate_recv_id(received_id):
    global last_recv_id

    # Ensure no duplicate ID is received
    if received_id == last_recv_id:
        # print(f"RN: {received_id} ... LAST:{last_recv_id}")
        print("[ID] Duplicate message ID detected")
        return False

    if not last_recv_id == 256 and (last_recv_id - received_id) > 5:
        print("[ID] Invalid message ID detected")

    # Accept the ID and update last received ID
    last_recv_id = received_id
    # print(f"[ID Validation] last_recv_id updated to: {last_recv_id}")  # Debug print
    return True


# Function to create a message header
def create_header(msg_type: int, flags: int, length: int, total_fragments: int, current_fragment: int, data: bytes) -> bytes:
    # Validate input parameters
    if msg_type < 0 or msg_type > 255:
        raise ValueError(f"msg_type out of range: {msg_type}")
    if total_fragments < 0 or total_fragments > 65535:
        raise ValueError(f"total_fragments out of range: {total_fragments}")
    if current_fragment < 0 or current_fragment > 65535:
        raise ValueError(f"current_fragment out of range: {current_fragment}")

    global errored  # Global error flag to introduce artificial corruption


    msg_id = generate_send_id()

    # Ensure the total packet size is within allowable limits (e.g., MTU - 1500 bytes for UDP)
    header_size = struct.calcsize("!B H B H H H")  # Calculate size of the header structure
    total_size = header_size + len(data)
    if total_size > 1500:  # Example MTU limit for UDP
        raise ValueError(f"Packet size exceeds the allowable limit: {total_size} bytes")

    # Construct the first byte by combining message type and flags
    first_byte = (msg_type << 4) | flags
    header_format = "!B H B H H H"

    if errored:  # Add erroneous data if the error flag is set
        data = data + bytes("random text".encode("utf-8"))

    crc = crc16(data)  # Calculate CRC for the data

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

# Function to perform a handshake
def handshake():
    print("[handshake] Connecting ...")
    syn_received = False

    while True:
        try:  # Attempt to receive SYN/SYN-ACK/ACK
            data, address = udp_socket.recvfrom(1500)  # Default size of socket
            header = data[:10]
            header_info = parse_header(header)
            msg_type = header_info["msg_type"]

            # Handle SYN message
            if msg_type == 1 and not syn_received:
                print("[Handshake] SYN received")
                syn_received = True
                header = create_header(2, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print(f"[Handshake] SYN-ACK sent")
                continue

            # Handle SYN-ACK message
            elif msg_type == 2 and not syn_received:
                print("[Handshake] SYN-ACK received")
                header = create_header(3, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print(f"[Handshake] ACK sent")
                return True

            # Handle ACK message
            elif msg_type == 3 and syn_received:
                print("[Handshake] ACK received")
                return True  # Handshake successful

        except socket.timeout:
            # If timeout occurs, retry by sending SYN
            header = create_header(1, 0, 0, 1, 1, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            print(f"[Handshake] SYN sent")
            syn_received = False
            continue

        except ConnectionResetError:
            continue

        # Handshake failed
        return False

# Function to close the connection using a 3-way handshake
def closing_handshake():
    global end_connection
    print("[Close] Initiating 3-way close handshake...")

    # Step 1: Send FIN message
    msg_type = 12  # FIN message type
    header = create_header(msg_type, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
    print("[Close] FIN sent")

    # Wait for FIN-ACK
    while True:
        try:
            data, _ = udp_socket.recvfrom(1500)
            header_info = parse_header(data[:10])
            if header_info["msg_type"] == 14:  # FIN-ACK
                print("[Close] FIN-ACK received")
                break
        except socket.timeout:
            print("[Close] Resending FIN...")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))

    # Step 2: Send ACK to complete handshake
    msg_type = 3  # ACK message type
    header = create_header(msg_type, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
    print("[Close] ACK sent")

    # Connection closed
    end_connection = True
    print("[Close] Connection closed successfully")

# Function to maintain a keep-alive heartbeat between peers
def keep_alive():
    global role, end_connection
    missed_heartbeats = 0

    if role == 1:  # Initiator of the heartbeat
        while not end_connection:
            # Send a heartbeat message
            header = create_header(5, 0, 0, 1, 1, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            # print("[Keep-alive] Sent heartbeat")
            time.sleep(2)

            # Check for acknowledgment
            response_received = False
            for _ in range(3):
                time.sleep(1)
                if not msg_queue.empty():
                    msg_queue.get()
                    response_received = True
                    # print("[Keep-alive] Heartbeat received")
                    missed_heartbeats = 0
                    break

            if not response_received:
                missed_heartbeats += 1
                # print(f"[Keep-alive] Missed heartbeat {missed_heartbeats}")

            if missed_heartbeats >= 3:
                print("[Keep-alive] Connection lost")
                end_connection = True
                break

    else:  # Listener for heartbeat
        while not end_connection:
            time.sleep(5)
            if not msg_queue.empty():
                msg_queue.get()
                # print("[Keep-alive] Heartbeat received")
                missed_heartbeats = 0
                header = create_header(5, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                # print("[Keep-alive] Sent heartbeat")
            else:
                missed_heartbeats += 1
                # print(f"[Keep-alive] Missed heartbeat {missed_heartbeats}")

            if missed_heartbeats >= 3:
                print("[Keep-alive] Connection lost")
                end_connection = True
                break



# Function to receive messages
def listener():
    global end_connection, errored
    file_name = "received file"
    received_file = False

    received_fragments = {}
    received_text_fragments = {}
    current_message_id = -1

    while not end_connection:
        try:
            # Attempt to receive a message
            data, address = udp_socket.recvfrom(1500)
            header = data[:10]
            body = data[10:]

            # Parse the received header
            header_info = parse_header(header)
            msg_type = header_info["msg_type"]
            current_fragment = header_info["current_fragment"]
            total_fragments = header_info["total_fragments"]
            received_crc = header_info["crc"]
            msg_id = header_info["msg_id"]

            computed_crc = crc16(body)

            # print(f"message id: {msg_id}")

            # Handle various message types
            if msg_type == 5:  # Heartbeat message
                msg_queue.put(data)
                continue

            if not validate_recv_id(msg_id):
                # Ak ID nie je validné, pošleme NACK
                send_nack()
                continue

            # Validate data size
            expected_length = header_info["length"]
            if len(body) != expected_length:
                print(f"[Listener] Data length mismatch: expected {expected_length}, received {len(body)}")
                send_nack()
                continue

            # print(f"RECEIVED: {received_crc}, COMPUTED: {computed_crc}")

            if received_crc != computed_crc:
                print(f"[Listener] CRC mismatch for fragment {current_fragment}, sending NACK")
                errored = False
                send_nack()
                continue

            if msg_type == 12:  # FIN message
                print("[Listener] FIN received, sending FIN-ACK...")
                # Send FIN-ACK
                msg_type = 14  # FIN-ACK message type
                header = create_header(msg_type, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, address)

                # Waiting for syn
                while True:
                    try:
                        ack_data, _ = udp_socket.recvfrom(1500)
                        ack_header_info = parse_header(ack_data[:10])
                        if ack_header_info["msg_type"] == 3:  # ACK received
                            print("[Listener] ACK received, connection closed")
                            end_connection = True
                            break
                    except socket.timeout:
                        print("[Listener] Resending FIN-ACK...")
                        udp_socket.sendto(header, address)

            if msg_type == 8:  # File name received
                file_name = body.decode('utf-8')
                print(f"[Listener] Received file name: {file_name}")
                continue

            if msg_type == 6:  # Receiving file in fragments
                # print(f"[Listener] Received and ACK sent for fragment {current_fragment}/{total_fragments}")

                received_fragments[current_fragment] = body
                print(f"[Listener] Received fragment {current_fragment}/{total_fragments}")
                send_ack()
                if current_fragment == total_fragments and not received_file:
                    current_file_data = b''.join(received_fragments[i] for i in range(1, total_fragments + 1))
                    save_received_file(file_name, current_file_data)
                    received_fragments = {}
                    print("[Listener] Received complete file and saved.")
                    received_file = True
                    # Handle complete file
                continue

            received_file = False

            if msg_type == 11:  # Receiving text message

                # if msg_id != current_message_id:
                #     received_text_fragments = {}
                #     current_message_id = msg_id

                send_ack()
                # print(f"[Listener] Received and ACK sent for fragment {current_fragment}/{total_fragments}")

                received_text_fragments[current_fragment] = body.decode("utf-8")
                # print(received_text_fragments)
                if current_fragment == total_fragments:
                    complete_message = ""
                    for i in range(1, total_fragments + 1):
                        if i in received_text_fragments:
                            complete_message += received_text_fragments[i]

                    print(f"[Listener] Received message: {complete_message}")
                    received_text_fragments = {}
                continue

            if msg_type == 7:  # End connection
                print("[Listener] Ending connection as requested.")
                end_connection = True
                break

            # if msg_type == 11:  # Receiving text message
            #     send_ack()
            #
            #     received_text_fragments[current_fragment] = body.decode("utf-8")
            #     print(f"[Listener] Received fragment {current_fragment}/{total_fragments}")
            #
            #     if len(received_text_fragments) >= (total_fragments + 1) // 2:
            #         complete_message = ""
            #         missing_fragments = []
            #
            #         for i in range(1, total_fragments + 1):
            #             if i in received_text_fragments:
            #                 complete_message += received_text_fragments[i]
            #
            #         print(f"[Listener] Received message: {complete_message}")
            #         received_text_fragments = {}
            #     continue

        except ConnectionResetError:
            # print("[Listener] Connection on the other side lost")
            continue

        except socket.timeout:
            continue


end_connection = False

errored = False
def sender():
    max_fragment_size = 1490  # Default (and max) size of fragment
    global end_connection, errored, default_directory
    while not end_connection:
        try:
            message = input(f"[Sender] Type message (/help):\n")

            # HELP MENU
            if message == "/help":
                print("\n" + "=" * 60)
                print("            Help Menu")
                print("=" * 60)
                commands = [
                    ("/help", "Zobrazí toto menu."),
                    ("/end", "Ukončie programu."),
                    ("/file <path>", "Odošle súbor na zadanú cestu."),
                    ("/error", "Vynúti chybu pre nasledujúci packet."),
                    ("/max <size>", "Nastaví maximálnu veľkosť fragmentu."),
                    ("/end fr", "Ukončí spojenia cez 3-w hs."),
                    ("/save", "Nastaví cestu, kde sa budú súbory ukladať."),
                ]

                for command, description in commands:
                    print(f"{command: <15} - {description}")

                print("=" * 60)
                continue

            # Check if the user wants to end the connection
            if message == "/end":
                print("ending connection ...")
                # send_end_message()
                end_connection = True
                break

            # Set address to save files here
            if message.startswith("/save"):
                command_parts = message.split(" ", 1)
                if len(command_parts) > 1:
                    default_directory = os.path.abspath(command_parts[1])
                    if not default_directory.endswith(os.path.sep):
                        default_directory += os.path.sep
                    print(f"Save path set to: {default_directory}")
                continue

            if message == "/end fr":
                print("[Sender] Ending connection with 3-way handshake...")
                closing_handshake()
                break

            # Handle error messages
            if message == "/error":
                errored = True
                print("Next fragment is errored")
                continue

            # Handle changing fragment size
            if message[:4] == "/max":
                max_fragment_size = int(message[4:])
                print(f"[Sender] Max size of fragment set to: {max_fragment_size} B")
                continue

            # Check if it's a command to send a file
            if message[:5] == "/file":
                command, file_path = message.split(" ", 1)
                send_file(file_path, max_fragment_size)
                continue

            # Handle normal text messages (not a file)
            send_message(message, max_fragment_size)
        except EOFError:
            end_connection = True
            break


def send_end_message():
    msg_type = 7  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_ack():
    msg_type = 15
    header = create_header(msg_type, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_nack():
    msg_type = 13
    header = create_header(msg_type, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_error_message():
    msg_type = 10
    header = create_header(msg_type, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))

# Function to send data
def send_file(file_path, max_fragment_size):
    time_spend = 0
    # Send file name first
    file_name = os.path.basename(file_path)
    header = create_header(8, 0, len(file_name), 1, 1, file_name.encode('utf-8'))
    udp_socket.sendto(header + file_name.encode('utf-8'), (REMOTE_IP, REMOTE_PORT))
    print(f"[Sender] Sent file name: {file_name}")

    # Read the file contents
    with open(file_path, "rb") as f:
        file_data = f.read()

    fragments = [file_data[i:i + max_fragment_size] for i in range(0, len(file_data), max_fragment_size)]
    total_fragments = len(fragments)

    starting_point = time.time()
    for current_fragment, fragment_data in enumerate(fragments, start=1):
        while True:
            udp_socket.settimeout(0.00001)
            msg_type = 6  # Message type for file fragment
            header = create_header(msg_type, 0, len(fragment_data), total_fragments, current_fragment,
                                   fragment_data)
            udp_socket.sendto(header + fragment_data, (REMOTE_IP, REMOTE_PORT))
            print(f"[Sender] Sent fragment {current_fragment}\tsize: {len(fragment_data)}B")

            # Wait for ACK or NACK
            try:

                ack_data, _ = udp_socket.recvfrom(1500)
                ack_header = parse_header(ack_data[:10])

                if ack_header["msg_type"] == 15:  # ACK2
                    # print(f"[Sender] ACK received for fragment {current_fragment}")
                    break  # Next fragment
                if ack_header["msg_type"] == 13:  # NACK
                    # print(f"[Sender] NACK received for fragment {current_fragment}, resending...")
                    continue
            except socket.timeout:
                # print(f"[Sender] Timeout waiting for ACK, resending fragment {current_fragment}...")
                continue
        ending_point = time.time()
        time_spend = ending_point - starting_point
    print(f"[Sender] Time spend on sending file {time_spend}")


def save_received_file(file_name, data):
    global default_directory
    # Ensure the directory exists, create if it doesn't
    os.makedirs(default_directory, exist_ok=True)
    # Normalize the path to handle different path formats
    save_path = os.path.join(default_directory, file_name)
    try:
        with open(save_path, "wb") as f:
            f.write(data)
        print(f"[Listener] File saved as {save_path}")
    except PermissionError:
        print(f"[Error] Permission denied. Cannot save file to {save_path}")
    except IOError as e:
        print(f"[Error] Could not save file: {e}")


def send_message(message, max_fragment_size):
    global errored
    header_size = 10
    max_payload_size = max_fragment_size

    # fragments = [message[i:i + max_payload_size] for i in range(0, len(message), max_payload_size)]
    # total_fragments = len(fragments)
    #
    # for current_fragment, fragment_data in enumerate(fragments, start=1):
    #     # Only send every other fragment (odd-numbered fragments)
    #     if current_fragment % 2 == 0:
    #         print(f"[Sender] Skipping fragment {current_fragment}")
    #         continue
    #
    #     while True:
    #         udp_socket.settimeout(0.2)  # Timeout for ACK
    #
    #         msg_type = 11  # Message type for text message
    #         flags = 0b0000
    #         length = len(fragment_data)
    #         header = create_header(msg_type, flags, length, total_fragments, current_fragment,
    #                                fragment_data.encode("utf-8"))
    #
    #         udp_socket.sendto(header + fragment_data.encode("utf-8"), (REMOTE_IP, REMOTE_PORT))
    #         print(f"[Sender] Sent fragment {current_fragment}\tsize: {len(fragment_data)}B")
    #
    #         # Wait for ACK or NACK
    #         try:
    #             ack_data, _ = udp_socket.recvfrom(1500)
    #             ack_header = parse_header(ack_data[:10])
    #
    #             if ack_header["msg_type"] == 15:  # ACK2
    #                 break  # Move to the next fragment
    #             elif ack_header["msg_type"] == 13:  # NACK
    #                 print(f"[Sender] NACK received for fragment {current_fragment}")
    #                 errored = False
    #                 continue  # Resend this fragment
    #         except socket.timeout:
    #             continue  # Resend on timeout


    fragments = [message[i:i + max_payload_size] for i in range(0, len(message), max_payload_size)]
    total_fragments = len(fragments)

    for current_fragment, fragment_data in enumerate(fragments, start=1):
        while True:
            udp_socket.settimeout(0.2)  # Timeout for ACK

            msg_type = 11  # Message type for text message
            flags = 0b0000
            length = len(fragment_data)
            header = create_header(msg_type, flags, length, total_fragments, current_fragment,
                                   fragment_data.encode("utf-8"))

            udp_socket.sendto(header + fragment_data.encode("utf-8"), (REMOTE_IP, REMOTE_PORT))
            print(f"[Sender] Sent fragment {current_fragment}\tsize: {len(fragment_data)}B")

            # Wait for ACK or NACK
            try:
                ack_data, _ = udp_socket.recvfrom(1500)
                ack_header = parse_header(ack_data[:10])

                if ack_header["msg_type"] == 15:  # ACK2
                    # print(f"[Sender] ACK received for fragment {current_fragment}")
                    break  # Move to the next fragment
                elif ack_header["msg_type"] == 13:  # NACK
                    print(f"[Sender] NACK received for fragment {current_fragment}")
                    errored = False
                    continue  # Resend this fragment
            except socket.timeout:
                # print(f"[Sender] Timeout waiting for ACK, resending msg")
                continue  # Resend on timeout


role = 0
def main():
    global role, end_connection

    the_handshake = handshake()
    if not the_handshake:
        print(f"[Handshake] Could not connect")
        return

    print(f"[Handshake] Connected")
    if LOCAL_PORT < REMOTE_PORT:
        # print("som L")
        role = 0
    else:
        # print("som W")
        role = 1

    listener_thread = threading.Thread(target=listener, daemon=True)
    sender_thread = threading.Thread(target=sender, daemon=True)
    keep_alive_thread = threading.Thread(target=keep_alive, daemon=True)  # New thread for keep-alive

    listener_thread.start()
    sender_thread.start()
    keep_alive_thread.start()

    listener_thread.join()
    sender_thread.join()
    keep_alive_thread.join()


main()
