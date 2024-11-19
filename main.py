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
udp_socket.settimeout(5)  # main timeout for handshake
udp_socket.bind((LOCAL_IP, LOCAL_PORT))


def create_header(msg_type: int, flags: int, length: int, msg_id: int, total_fragments: int, current_fragment: int, data: bytes) -> bytes:
    # Merging type of msg and flag into one byte and formating header

    if msg_type < 0 or msg_type > 255:
        raise ValueError(f"msg_type out of range: {msg_type}")
    if msg_id < 0 or msg_id > 255:
        raise ValueError(f"msg_id out of range: {msg_id}")
    if total_fragments < 0 or total_fragments > 65535:
        raise ValueError(f"total_fragments out of range: {total_fragments}")
    if current_fragment < 0 or current_fragment > 65535:
        raise ValueError(f"current_fragment out of range: {current_fragment}")

    first_byte = (msg_type << 4) | flags
    header_format = "!B H B H H H"
    # Calculating crc of data (the message)
    crc = crc16.crc16xmodem(data)
    # Returning struct with data at the end
    return struct.pack(header_format, first_byte, length, msg_id, total_fragments, current_fragment, crc)


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
    # Roles are set right after handshake was successful
    if role == 1:  # The one who will send KA first
        while not end_connection:
            time.sleep(5)  # Send keep-alive every 5 seconds
            header = create_header(5, 0, 0, 0, 1, 1, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            # print("[Keep-alive] Still connected")

            time.sleep(10)  # Check every 10 sec queue
            if not msg_queue.empty():
                # Do not need to check what is inside
                continue
            break

    else:  # The one who will listen first
        while not end_connection:
            time.sleep(8)  # Sleep and wait for K-A msg
            if not msg_queue.empty():  # Check if the queue is not empty
                header = create_header(5, 0, 0, 0, 1, 1, b"")
                # Send K-A message after receiving one
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                # print("[Keep-alive] Still connected")
                time.sleep(7)
                continue
            break
    print("[Keep-alive] Connection lost")


msg_id = 0
last_received_msg_id = -1


stop_and_wait = False


# def listener():
#     global stop_and_wait
#     global last_received_msg_id
#     global end_connection
#
#     received_fragments = {}
#     expected_fragments = None
#     current_file_data = b""
#     file_name = None
#
#     received_fragments = {}
#     while not end_connection:
#         try:  # Try to receive msg
#             data, address = udp_socket.recvfrom(1024)
#             # Split msg into header and body
#             header = data[:10]
#             body = data[10:]
#             header_info = parse_header(header)
#             # Getting parts of header from received msg
#             msg_type = header_info["msg_type"]
#             received_crc = header_info["crc"]
#             total_fragments = header_info['total_fragments']
#             current_fragment = header_info['current_fragment']
#             # Calculating crc to check if the message is correctly received
#             computed_crc = crc16.crc16xmodem(body)
#
#
#
            # if msg_type == 8:  # Prijatie názvu súboru
            #     file_name = body.decode('utf-8')
            #     print(f"[Listener] Received file name: {file_name}")
            #     continue
            #
            # if msg_type == 6:  # Prijatie fragmentu súboru
            #     # if received_crc != computed_crc:
            #     #     print(f"[Listener] Fragment {current_fragment} CRC mismatch.")
            #     #     continue
            #
            #     received_fragments[current_fragment] = body
            #     print(f"[Listener] Received fragment {current_fragment}/{total_fragments}")
            #
            #     if current_fragment == total_fragments:
            #         current_file_data = b''.join(received_fragments[i] for i in range(1, total_fragments + 1))
            #         save_received_file(file_name, current_file_data)
            #         received_fragments = {}
            #     continue
#
            # if msg_type == 5:  # If msg is 0101 (Keep-alive) put that into Queue
            #     msg_queue.put(data)
            #     continue  # "Ignore K-A" and continue receiving
#
#             if current_fragment == 1:
#                 received_fragments = {}  # Resetting dictionary for fragments
#
#             if received_crc != computed_crc:
#                 header = create_header(4, 0, 0, 0, 1, 1, b"")
#                 udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
#                 print(f"[Listener] NACK sent, wrong CRC")
#
#             received_fragments[current_fragment] = body.decode("utf-8")  # Adding fragment to dictionary
#
#             if current_fragment == total_fragments:
#                 full_message = ''.join(received_fragments[i] for i in range(1, total_fragments + 1))  # Merging fragments into one message
#                 print(f"[Listener] {full_message}")
#                 continue
#
#             print(f"[Listener] {body.decode("utf-8")}")
#
#             if msg_type == 7:
#                 print("[Listener] Ending connection based on user action")
#                 end_connection = True
#                 break
#
#             if last_received_msg_id == msg_id:
#                 print(f"[Listener] Duplicate ID of msg!")
#             else:
#                 last_received_msg_id = msg_id
#
#         except socket.timeout:
#             continue


def listener():
    global last_received_msg_id, end_connection

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




            if msg_type in {6, 11}:  # File fragment or message fragment
                if received_crc != computed_crc:
                    print(f"[Listener] CRC mismatch for fragment {current_fragment}, sending NACK")
                    send_nack()
                    continue

                send_ack()
                print(f"[Listener] Received and ACK sent for fragment {current_fragment}/{total_fragments}")

                received_fragments[current_fragment] = body
                if current_fragment == total_fragments:
                    print("[Listener] Received complete message or file.")
                    # Handle complete message or file
                    continue

            if msg_type == 5:  # If msg is 0101 (Keep-alive) put that into Queue
                msg_queue.put(data)
                continue  # "Ignore K-A" and continue receiving

            if msg_type == 8:  # File name
                file_name = body.decode('utf-8')
                print(f"[Listener] Received file name: {file_name}")
                send_ack()
                continue

            if msg_type == 7:  # End connection
                print("[Listener] Ending connection as requested.")
                end_connection = True
                break

        except socket.timeout:
            continue


end_connection = False


def sender():
    max_fragment_size = 500  # Default size of fragment
    global end_connection
    while not end_connection:
        try:
            message = input(f"[Sender] Type message:\n")

            # Check if the user wants to end the connection
            if message == "/end":
                send_end_message()
                end_connection = True
                break

            # Handle error messages
            if message == "/error":
                send_error_message()
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
    header = create_header(msg_type, 0, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_ack():
    msg_type = 15  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_nack():
    msg_type = 13  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_error_message():
    msg_type = 10  # msg type is 0111 (End Connection)
    header = create_header(msg_type, 0, 0, 0, 1, 1, b"")
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

    for current_fragment, fragment_data in enumerate(fragments, start=1):
        while True:
            msg_type = 6  # Message type for file fragment
            header = create_header(msg_type, 0, len(fragment_data) + 10, msg_id, total_fragments, current_fragment,
                                   fragment_data)
            udp_socket.sendto(header + fragment_data, (REMOTE_IP, REMOTE_PORT))
            print(f"[Sender] Sent fragment {current_fragment}/{total_fragments}")

            # Wait for ACK or NACK
            try:
                udp_socket.settimeout(2)
                ack_data, _ = udp_socket.recvfrom(1024)
                ack_header = parse_header(ack_data[:10])

                if ack_header["msg_type"] == 15:  # ACK
                    print(f"[Sender] ACK received for fragment {current_fragment}")
                    break  # Next fragment
                elif ack_header["msg_type"] == 13:  # NACK
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

    msg_id = (msg_id + 1) % 256

    fragments = [message[i:i + max_payload_size] for i in range(0, len(message), max_payload_size)]
    total_fragments = len(fragments)
    for current_fragment, fragment_data in enumerate(fragments, start=1):
        while True:
            msg_type = 11  # Message type for text message
            flags = 0b0000
            length = len(fragment_data) + header_size
            header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment,
                                   fragment_data.encode("utf-8"))

            udp_socket.sendto(header + fragment_data.encode("utf-8"), (REMOTE_IP, REMOTE_PORT))
            print(f"[Sender] Sent fragment {current_fragment}/{total_fragments}: {fragment_data}")

            # Wait for ACK or NACK
            try:
                udp_socket.settimeout(2)  # Timeout for ACK
                ack_data, _ = udp_socket.recvfrom(1024)
                ack_header = parse_header(ack_data[:10])

                if ack_header["msg_type"] == 15:  # ACK
                    print(f"[Sender] ACK received for fragment {current_fragment}")
                    break  # Move to the next fragment
                elif ack_header["msg_type"] == 13:  # NACK
                    print(f"[Sender] NACK received for fragment {current_fragment}, resending...")
                    continue  # Resend this fragment
            except socket.timeout:
                print(f"[Sender] Timeout waiting for ACK, resending fragment {current_fragment}...")
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