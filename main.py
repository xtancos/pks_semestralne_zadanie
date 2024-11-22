import socket
import threading
import argparse
import struct
import time
import queue
import crc16
import os


# All messages are appending to Main queue, so they will be separated
msg_queue = queue.Queue()

# Arguments for program !!! HAS TO BE CHANGED FOR STDIN !!!
parser = argparse.ArgumentParser()
parser.add_argument("--source", type=str)
parser.add_argument("--destination", type=str)
parser.add_argument("--src_port", type=int)
parser.add_argument("--dest_port", type=int)
args = parser.parse_args()

LOCAL_IP = args.source
LOCAL_PORT = args.src_port

REMOTE_IP = args.destination
REMOTE_PORT = args.dest_port

# Creating IPV4, UDP socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.settimeout(3)  # main timeout for handshake
udp_socket.bind((LOCAL_IP, LOCAL_PORT))


def create_header(msg_type: int, flags: int, length: int, msg_id: int, total_fragments: int, current_fragment: int, data: bytes) -> bytes:
    if msg_type < 0 or msg_type > 255:
        raise ValueError(f"msg_type out of range: {msg_type}")
    if msg_id < 0 or msg_id > 255:
        raise ValueError(f"msg_id out of range: {msg_id}")
    if total_fragments < 0 or total_fragments > 65535:
        raise ValueError(f"total_fragments out of range: {total_fragments}")
    if current_fragment < 0 or current_fragment > 65535:
        raise ValueError(f"current_fragment out of range: {current_fragment}")

    global errored

    first_byte = (msg_type << 4) | flags
    header_format = "!B H B H H H"

    if errored:
        data = data + bytes("random text".encode("utf-8"))

    crc = crc16.crc16xmodem(data)  # Compute CRC using crcmod
    return struct.pack(header_format, first_byte, length, msg_id, total_fragments, current_fragment, crc)

# def create_header(msg_type: int, flags: int, length: int, msg_id: int, total_fragments: int, current_fragment: int, data: bytes) -> bytes:
#
#
#     if msg_type < 0 or msg_type > 255:
#         raise ValueError(f"msg_type out of range: {msg_type}")
#     if msg_id < 0 or msg_id > 255:
#         raise ValueError(f"msg_id out of range: {msg_id}")
#     if total_fragments < 0 or total_fragments > 65535:
#         raise ValueError(f"total_fragments out of range: {total_fragments}")
#     if current_fragment < 0 or current_fragment > 65535:
#         raise ValueError(f"current_fragment out of range: {current_fragment}")
#
#     # Merging type of msg and flag into one byte and formating header
#     first_byte = (msg_type << 4) | flags
#     header_format = "!B H B H H H"
#     # Calculating crc of data (the message)
#     crc = crc16.crc16xmodem(data)
#     # Returning struct with data at the end
#     return struct.pack(header_format, first_byte, length, msg_id, total_fragments, current_fragment, crc)


def parse_header(header: bytes):
    # Formating header
    header_format = "!B H B H H H"
    unpacked = struct.unpack(header_format, header)
    # Unpacking first byte, splitting it into msg type and flag
    first_byte = unpacked[0]
    msg_type = (first_byte >> 4) & 0xF
    flags = first_byte & 0xF
    # Returning dictionary
    return {
        "msg_type": msg_type,
        "flags": flags,
        "length": unpacked[1],
        "msg_id": unpacked[2],
        "total_fragments": unpacked[3],
        "current_fragment": unpacked[4],
        "crc": unpacked[5]
    }


def handshake():
    print("[handshake] Connecting ...")
    syn_received = False

    while True:
        # try to receive SYN/SYN-ACK/ACK
        try:
            # Getting msg_type
            data, address = udp_socket.recvfrom(1024)  # Default size of socket
            header = data[:10]
            header_info = parse_header(header)
            msg_type = header_info["msg_type"]

            if msg_type == 1 and not syn_received:  # msg type: 0001
                print("[Handshake] SYN received")
                syn_received = True
                header = create_header(2, 0, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print(f"[Handshake] SYN-ACK sent")
                continue

            elif msg_type == 2 and not syn_received:  # msg type: 0010
                print("[Handshake] SYN-ACK received")
                header = create_header(3, 0, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print(f"[Handshake] ACK sent")
                return True  # Handshake successful

            elif msg_type == 3 and syn_received:  # msg type: 0011
                print("[Handshake] ACK received")
                return True  # Handshake successful

        except socket.timeout:
            header = create_header(1, 0, 0, 0, 1, 1, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            print(f"[Handshake] SYN sent")
            syn_received = False
            continue  # Repeat handshake

        return False  # Handshake failed


def keep_alive():
    global role, end_connection
    missed_heartbeats = 0

    if role == 1:  # Initiator of the heartbeat
        while not end_connection:
            # Send heartbeat
            header = create_header(5, 0, 0, 0, 1, 1, b"")
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
            if not msg_queue.empty():  # Check for incoming heartbeat
                msg_queue.get()  # Consume the message
                # print("[Keep-alive] Heartbeat received")
                missed_heartbeats = 0

                # Send response
                header = create_header(5, 0, 0, 0, 1, 1, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                # print("[Keep-alive] Sent heartbeat")
            else:
                missed_heartbeats += 1
                # print(f"[Keep-alive] Missed heartbeat {missed_heartbeats}")

            if missed_heartbeats >= 3:
                print("[Keep-alive] Connection lost")
                end_connection = True
                break



def listener():
    global last_received_msg_id, end_connection, msg_id, errored
    file_name = "received file"

    received_fragments = {}
    while not end_connection:
        try:
            data, address = udp_socket.recvfrom(1024)
            header = data[:10]
            body = data[10:]
            header_info = parse_header(header)

            msg_type = header_info["msg_type"]
            current_fragment = header_info["current_fragment"]
            total_fragments = header_info["total_fragments"]
            received_crc = header_info["crc"]
            computed_crc = crc16.crc16xmodem(body)

            if msg_type == 5:  # If msg is 0101 (Keep-alive) put that into Queue
                msg_queue.put(data)
                continue  # "Ignore K-A" and continue receiving

            print(f"message id: {msg_id}")

            if last_received_msg_id == msg_id:
                print("rovnake ID")
                errored = False
                time.sleep(0.5)
                # continue

            last_received_msg_id = msg_id

            print(f"RECEIVED: {received_crc}, COMPUTED: {computed_crc}")

            if received_crc != computed_crc:
                print(f"[Listener] CRC mismatch for fragment {current_fragment}, sending NACK")
                errored = False
                send_nack()
                continue

            if msg_type == 8:  # Prijatie názvu súboru
                file_name = body.decode('utf-8')
                print(f"[Listener] Received file name: {file_name}")
                continue

            if msg_type == 6:  # Prijatie fragmentu súboru

                send_ack()
                print(f"[Listener] Received and ACK sent for fragment {current_fragment}/{total_fragments}")

                received_fragments[current_fragment] = body
                print(f"[Listener] Received fragment {current_fragment}/{total_fragments}")
                if current_fragment == total_fragments:
                    current_file_data = b''.join(received_fragments[i] for i in range(1, total_fragments + 1))
                    save_received_file(file_name, current_file_data)
                    received_fragments = {}
                    print("[Listener] Received complete file and saved.")
                    # Handle complete file
                continue

            if msg_type == 11:

                send_ack()
                print(f"[Listener] Received and ACK sent for fragment {current_fragment}/{total_fragments}")

                received_fragments[current_fragment] = body
                if current_fragment == total_fragments:
                    #print("[Listener] Received complete message.")
                    print(f"[Listener] {body.decode("utf-8")}")

                    # Handle complete message
                    continue

            if msg_type == 7:  # End connection
                print("[Listener] Ending connection as requested.")
                end_connection = True
                break

        except ConnectionResetError:
            # print("[Listener] Connection on the other side lost")
            continue

        except socket.timeout:
            continue


end_connection = False

errored = False
def sender():
    max_fragment_size = 500  # Default size of fragment
    global end_connection, errored
    while not end_connection:
        try:
            message = input(f"[Sender] Type message:\n")

            # Check if the user wants to end the connection
            if message == "/end":
                print("ending connection ...")
                # send_end_message()
                end_connection = True
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
    global msg_id
    msg_type = 7  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, msg_id, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_ack():
    global msg_id
    msg_type = 15  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, msg_id, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_nack():
    global msg_id
    msg_type = 13  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, msg_id, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_error_message():
    global msg_id
    msg_type = 10  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, msg_id, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


# def send_file(file_path, max_fragment_size):
#     global msg_id
#     msg_id = (msg_id + 1) % 256
#
#     # Send file name first
#     file_name = os.path.basename(file_path)
#     header = create_header(8, 0, len(file_name), msg_id, 1, 1, file_name.encode('utf-8'))
#     udp_socket.sendto(header + file_name.encode('utf-8'), (REMOTE_IP, REMOTE_PORT))
#     print(f"[Sender] Sent file name: {file_name}")
#
#     # Read the file and send in fragments
#     with open(file_path, "rb") as f:
#         file_data = f.read()
#
#     fragments = [file_data[i:i + max_fragment_size] for i in range(0, len(file_data), max_fragment_size)]
#     total_fragments = len(fragments)
#
#     for current_fragment, fragment_data in enumerate(fragments, start=1):
#         msg_type = 6  # Message type for file fragment
#         header = create_header(msg_type, 0, len(fragment_data) + 10, msg_id, total_fragments, current_fragment, fragment_data)
#         udp_socket.sendto(header + fragment_data, (REMOTE_IP, REMOTE_PORT))
#         print(f"[Sender] Sent fragment {current_fragment}/{total_fragments}")

def send_file(file_path, max_fragment_size):
    global msg_id
    msg_id = (msg_id + 1) % 256
    print(f"Teraz som zmenil msg IDna : {msg_id}")

    # Send file name first
    file_name = os.path.basename(file_path)
    header = create_header(8, 0, len(file_name), msg_id, 1, 1, file_name.encode('utf-8'))
    udp_socket.sendto(header + file_name.encode('utf-8'), (REMOTE_IP, REMOTE_PORT))
    print(f"[Sender] Sent file name: {file_name}")

    # Read the file and send in fragments
    with open(file_path, "rb") as f:
        file_data = f.read()

    fragments = [file_data[i:i + max_fragment_size] for i in range(0, len(file_data), max_fragment_size)]
    total_fragments = len(fragments)

    udp_socket.settimeout(1)

    for current_fragment, fragment_data in enumerate(fragments, start=1):
        while True:
            msg_type = 6  # Message type for file fragment
            header = create_header(msg_type, 0, len(fragment_data) + 10, msg_id, total_fragments, current_fragment,
                                   fragment_data)
            udp_socket.sendto(header + fragment_data, (REMOTE_IP, REMOTE_PORT))
            print(f"[Sender] Sent fragment {current_fragment}/{total_fragments}")

            # Wait for ACK or NACK
            try:

                ack_data, _ = udp_socket.recvfrom(1024)
                ack_header = parse_header(ack_data[:10])

                if ack_header["msg_type"] == 15:  # ACK
                    print(f"[Sender] ACK received for fragment {current_fragment}")
                    break  # Next fragment
                if ack_header["msg_type"] == 13:  # NACK
                    print(f"[Sender] NACK received for fragment {current_fragment}, resending...")
                    continue
            except socket.timeout:
                print(f"[Sender] Timeout waiting for ACK, resending fragment {current_fragment}...")
                continue


def save_received_file(file_name, data):
    save_path = f"C:/Users/damia/Desktop/PKS_DOWNLOAD/{file_name}"
    with open(save_path, "wb") as f:
        f.write(data)
    print(f"[Listener] File saved as {save_path}")


def send_message(message, max_fragment_size):
    global msg_id
    header_size = 10
    max_payload_size = max_fragment_size

    # msg_id = (msg_id + 1) % 256
    current_msg_id = get_next_msg_id()
    print(f"Teraz som zmenil msg IDna : {msg_id}")

    fragments = [message[i:i + max_payload_size] for i in range(0, len(message), max_payload_size)]
    total_fragments = len(fragments)
    udp_socket.settimeout(3)  # Timeout for ACK

    for current_fragment, fragment_data in enumerate(fragments, start=1):
        while True:
            msg_type = 11  # Message type for text message
            flags = 0b0000
            length = len(fragment_data) + header_size
            header = create_header(msg_type, flags, length, current_msg_id, total_fragments, current_fragment,
                                   fragment_data.encode("utf-8"))

            udp_socket.sendto(header + fragment_data.encode("utf-8"), (REMOTE_IP, REMOTE_PORT))
            print(f"[Sender] Sent fragment {current_fragment}/{total_fragments}: {fragment_data}")

            # Wait for ACK or NACK
            try:
                ack_data, _ = udp_socket.recvfrom(1024)
                ack_header = parse_header(ack_data[:10])

                if ack_header["msg_type"] == 15:  # ACK
                    print(f"[Sender] ACK received for fragment {current_fragment}")
                    break  # Move to the next fragment
                elif ack_header["msg_type"] == 13:  # NACK
                    print(f"[Sender] NACK received for fragment {current_fragment}, resending...")
                    continue  # Resend this fragment
            except socket.timeout:
                print(f"[Sender] Timeout waiting for ACK, resending msg")
                continue  # Resend on timeout


# def send_message(message, max_fragment_size):
#     global msg_id
#     header_size = 10
#     max_payload_size = max_fragment_size
#
#     msg_id = (msg_id + 1) % 256
#
#     fragments = [message[i:i + max_payload_size] for i in range(0, len(message), max_payload_size)]
#     total_fragments = len(fragments)
#     for current_fragment, fragment_data in enumerate(fragments, start=1):
#         while True:
#             msg_type = 11  # Message type for text message
#             flags = 0b0000
#             length = len(fragment_data) + header_size
#             header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment,
#                                    fragment_data.encode("utf-8"))
#
#             udp_socket.sendto(header + fragment_data.encode("utf-8"), (REMOTE_IP, REMOTE_PORT))
#             print(f"[Sender] Sent fragment {current_fragment}/{total_fragments}: {fragment_data}")
#
#             # Wait for ACK or NACK
#             try:
#                 udp_socket.settimeout(2)  # Timeout for ACK
#                 ack_data, _ = udp_socket.recvfrom(1024)
#                 ack_header = parse_header(ack_data[:10])
#
#                 if ack_header["msg_type"] == 15:  # ACK
#                     print(f"[Sender] ACK received for fragment {current_fragment}")
#                     break  # Move to the next fragment
#                 elif ack_header["msg_type"] == 13:  # NACK
#                     print(f"[Sender] NACK received for fragment {current_fragment}, resending...")
#                     continue  # Resend this fragment
#             except socket.timeout:
#                 print(f"[Sender] Timeout waiting for ACK, resending fragment {current_fragment}...")
#                 continue  # Resend on timeout

# Globálne premenne na správu ID
msg_id = 0
last_received_msg_id = -1

# Funkcia na inkrementáciu a resetovanie ID
def get_next_msg_id():
    global msg_id
    msg_id = (msg_id + 1) % 256  # Cyklus ID od 0 po 255
    return msg_id

# Resetovanie ID pri ukončení spojenia
def reset_msg_id():
    global msg_id
    msg_id = 0


role = 0
def main():
    global role, end_connection

    the_handshake = handshake()
    if not the_handshake:
        print(f"[Handshake] Could not connect")
        return

    print(f"[Handshake] Connected")
    if LOCAL_PORT < REMOTE_PORT:
        #print("som L")
        role = 0
    else:
        #print("som W")
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