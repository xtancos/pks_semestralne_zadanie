import socket
import threading
import argparse
import struct
import time
import queue
import crc16

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
udp_socket.settimeout(20)  # main timeout for handshake
udp_socket.bind((LOCAL_IP, LOCAL_PORT))


def create_header(msg_type: int, flags: int, length: int, msg_id: int, total_fragments: int, current_fragment: int, data: bytes) -> bytes:
    # Merging type of msg and flag into one byte
    first_byte = (msg_type << 4) | flags
    header_format = "!B H B B B H %ds" % len(data)
    # Calculating crc of data (the message)
    crc = crc16.crc16xmodem(data)

    return struct.pack(header_format, first_byte, length, msg_id, total_fragments, current_fragment, crc, data)


# def create_header(msg_type: int, flags: int, length: int, msg_id: int, total_fragments: int, current_fragment: int, crc: int) -> bytes:
#     """
#     Vytvorí hlavičku správy.
#     :param msg_type: Typ správy (4 bity).
#     :param flags: Flags (4 bity).
#     :param length: Dĺžka správy (16 bitov).
#     :param msg_id: ID správy (8 bitov).
#     :param total_fragments: Celkový počet fragmentov (8 bitov).
#     :param current_fragment: Aktuálny fragment (8 bitov).
#     :param crc: CRC16 na kontrolu integrity (16 bitov).
#     :return: Binárna hlavička.
#     """
#     # Prvý bajt: msg_type (4 bity) a flags (4 bity) sú spojené do jedného bajtu
#     first_byte = (msg_type << 4) | flags
#
#     # Definícia formátu: B = 1 byte, H = 2 bytes
#     header_format = "!B H B B B H"  # ! -> big-endian, B = 1 byte, H = 2 bytes
#
#     return struct.pack(header_format, first_byte, length, msg_id, total_fragments, current_fragment, crc)


def parse_header(header: bytes):
    """
    Parsuje binárnu hlavičku a extrahuje hodnoty.
    :param header: Binárna hlavička.
    :return: Dictionary s extrahovanými hodnotami.
    """
    header_format = "!B H B B B H"
    unpacked = struct.unpack(header_format, header)

    # Rozdelíme prvý bajt na msg_type (4 bity) a flags (4 bity)
    first_byte = unpacked[0]
    msg_type = (first_byte >> 4) & 0xF  # extrahujeme msg_type (4 bity)
    flags = first_byte & 0xF  # extrahujeme flags (4 bity)

    # Vytvoríme slovník pre hodnoty
    header_info = {
        "msg_type": msg_type,
        "flags": flags,
        "length": unpacked[1],
        "msg_id": unpacked[2],
        "total_fragments": unpacked[3],
        "current_fragment": unpacked[4],
        "crc": unpacked[5]
    }

    # Vytlačíme hodnoty
    print("Unpacked Header Info:")
    for key, value in header_info.items():
        print(f"{key}: {value}")

    # Vrátime všetky extrahované hodnoty ako slovník
    return header_info



def handshake():
    print("[handshake] Starting handshake ...")

    msg_type = 0b0000
    flags = 0b0000
    length = 0
    msg_id = 0
    total_fragments = 1
    current_fragment = 1
    crc = 0

    syn_received = False

    while True:
        # try to receive SYN
        try:
            data, address = udp_socket.recvfrom(1024)
            header = data[:8]
            header_info = parse_header(header)

            address_info = address
            msg_type = header_info["msg_type"]
            flags = header_info["flags"]
            length = header_info["length"]
            msg_id = header_info["msg_id"]
            crc = header_info["crc"]

            print(msg_type, type(msg_type))

            if msg_type == 1 and not syn_received:
                print("[Handshake] SYN received]")
                syn_received = True

                msg_type = 0b0010

                header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print(f"[Handshake]: SYN-ACK sent")
                continue

            elif msg_type == 2 and not syn_received:
                print("[Handshake] SYN-ACK received]")

                msg_type = 0b0011
                header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment, b"")
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print(f"[Handshake]: ACK sent")
                print(f"[Handshake]: Completed !!!")
                return True

            elif msg_type == 3 and syn_received:
                print("[Handshake] ACK received]")
                print(f"[Handshake]: Completed !!!")
                return True

        except socket.timeout:

            msg_type = 1

            header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment, b"")
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            print(f"[Handshake]: SYN sent")
            syn_received = False
            continue

        print("[Handshake] Failed !!!")
        return False


def keep_alive():
    global role

    if role == 1:  # budem akoby odosielatel prveho keepalive
        while True:

            time.sleep(5)  # Send keep-alive every 5 seconds

            msg_type = 0b0101  # Keep-alive message type
            flags = 0b0000  # Predvolené flagy
            length = 0  # Keep-alive správy nemajú telo
            total_fragments = 1
            current_fragment = 1
            crc = 0  # No CRC for keep-alive

            # Vytvorenie hlavičky s aktuálnym msg_id
            header = create_header(msg_type, flags, length, 0, total_fragments, current_fragment, b"")

            # Odošleme keep-alive správu
            udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
            print("[Keep-alive]: Sent keep-alive message")

            time.sleep(10)
            if not msg_queue.empty():
                # Zoberieme správu z fronty
                data = msg_queue.get_nowait()

                header = data
                # Parsujeme hlavičku
                header_info = parse_header(header)
                continue

            print("[Keep-alive]: TIMEOUT !!!")
            break

    else:  # tu budem najprv pocuvat a az tak poslem xd
        while True:
            time.sleep(8)  # Send keep-alive every 5 seconds
            if not msg_queue.empty():
                # Zoberieme správu z fronty
                data = msg_queue.get_nowait()

                header = data
                # Parsujeme hlavičku
                header_info = parse_header(header)

                # time.sleep(5)  # Send keep-alive every 5 seconds

                msg_type = 0b0101  # Keep-alive message type
                flags = 0b0000  # Predvolené flagy
                length = 0  # Keep-alive správy nemajú telo
                total_fragments = 1
                current_fragment = 1
                crc = 0  # No CRC for keep-alive

                # Vytvorenie hlavičky s aktuálnym msg_id
                header = create_header(msg_type, flags, length, 0, total_fragments, current_fragment, b"")

                # Odošleme keep-alive správu
                udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
                print("[Keep-alive]: Sent keep-alive message")
                time.sleep(7)
                continue

            print("[Keep-alive]: TIMEOUT !!!")
            break

    print("[KA] Connection RIP")
    return False


msg_id = 0
last_received_msg_id = -1


# def listener():
#     global last_received_msg_id  # Access the global variable to track the last received msg_id
#     global end_connection
#     while not end_connection:
#         try:
#             # Prijmeme paket (max 1024 bajtov)
#             data, address = udp_socket.recvfrom(1024)
#
#             # Rozdelíme paket na hlavičku a telo správy
#             header = data[:8]  # Predpokladáme, že hlavička má 8 bajtov
#             body = data[8:]  # Ostatné je samotný obsah správy
#
#             # Parsujeme hlavičku
#             header_info = parse_header(header)
#
#             header_info = parse_header(header)
#             msg_type = header_info['msg_type']
#             msg_id = header_info['msg_id']
#
#             # Zobrazenie informácií z hlavičky
#             # print(f"[Prijaté od {address}]:")
#             # print(f"Typ správy: {header_info['msg_type']}")
#             # print(f"Flags: {header_info['flags']}")
#             # print(f"Dĺžka správy: {header_info['length']} bajtov")
#             # print(f"ID správy: {msg_id}")
#             # print(f"Celkový počet fragmentov: {header_info['total_fragments']}")
#             # print(f"Aktuálny fragment: {header_info['current_fragment']}")
#             # print(f"CRC: {header_info['crc']}")
#
#             # Zobrazenie obsahu správy (telo)
#             print(f"Dáta: {body.decode()}")  # Telo správy je reťazec
#
#             if msg_type == 5:
#                 msg_queue.put(data)
#
#             if msg_type == 7:  # ukoncenie spojenia
#                 print("[Listener] ukoncujem spojenie, zaslana sprava na END")
#                 end_connection = True
#                 break
#
#             # Kontrola, či je správa nová (nie duplikát)
#             if last_received_msg_id == msg_id:
#                 print(f"[Warning] Duplikát správy s ID {msg_id}!")
#             else:
#                 last_received_msg_id = msg_id  # Uložíme ID tejto správy ako posledné prijaté
#
#         except socket.timeout:
#             continue


def listener():
    global last_received_msg_id
    global end_connection
    received_fragments = {}
    while not end_connection:
        try:
            data, address = udp_socket.recvfrom(1024)

            header = data[:8]
            print(header)
            body = data[8:]
            print(body.decode("utf-8"))
            header_info = parse_header(header)

            msg_type = header_info["msg_type"]

            # Overenie CRC
            received_crc = header_info["crc"]
            computed_crc = crc16.crc16xmodem(body)
            print(f"DRUHECRC: {computed_crc}")
            # msg_id = header_info['msg_id']
            total_fragments = header_info['total_fragments']
            current_fragment = header_info['current_fragment']

            if msg_type == 5:
                msg_queue.put(data)
                continue

            # reseting all fragments
            if current_fragment == 1:
                received_fragments = {}

            print(f"KED SA FRAGMENTUJE SPRAVA XD: {body.decode()}")  # Telo správy je reťazec

            received_fragments[current_fragment] = body.decode()
            if current_fragment == total_fragments:
                full_message = ''.join(received_fragments[i] for i in range(1, total_fragments + 1))
                print(f"[Prijatá správa]: {full_message}")
                continue

            if received_crc != computed_crc:
                print(f"[Warning] CRC mismatch! Received: {received_crc}, Computed: {computed_crc}")

            print(f"Dáta: {body.decode()}")  # Telo správy je reťazec

            if msg_type == 7:
                print("[Listener] ukoncujem spojenie, zaslana sprava na END")
                end_connection = True
                break

            if last_received_msg_id == msg_id:
                print(f"[Warning] Duplikát správy s ID {msg_id}!")
            else:
                last_received_msg_id = msg_id

        except socket.timeout:
            continue


end_connection = False


# def sender():
#     global msg_id  # Access the global msg_id
#     global end_connection
#
#     while not end_connection:
#         message = input("Zadajte správu na odoslanie: ")
#
#         if message == "/end":
#             # Skôr než odoslať správu, vytvorte hlavičku
#             msg_type = 0b0111  # posielame text
#             flags = 0b0000  # Predvolené žiadne flagy
#             length = len(message)  # Dĺžka správy
#             total_fragments = 1  # Predpokladáme, že správa je len jeden fragment
#             current_fragment = 1  # Tento fragment je 1
#             crc = 0  # CRC, ktoré môžete vypočítať neskôr, teraz je predvolené na 0
#
#             header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment, crc)
#             udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
#             print("[Listener] ukoncujem spojenie, zaslana sprava na END")
#             end_connection = True
#             break
#
#
#         # Skôr než odoslať správu, vytvorte hlavičku
#         msg_type = 0b0110  # posielame text
#         flags = 0b0000  # Predvolené žiadne flagy
#         length = len(message)  # Dĺžka správy
#         total_fragments = 1  # Predpokladáme, že správa je len jeden fragment
#         current_fragment = 1  # Tento fragment je 1
#         crc = 0  # CRC, ktoré môžete vypočítať neskôr, teraz je predvolené na 0
#
#         # Vytvorenie hlavičky s aktuálnym msg_id
#         header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment, crc)
#
#         # Odošleme správy: hlavička + dáta
#         udp_socket.sendto(header + message.encode(), (REMOTE_IP, REMOTE_PORT))
#         print(f"[Odoslané]: {message}")
#
#         # Increment msg_id and wrap around using modulo 255
#         msg_id = (msg_id + 1) % 256  # Reset to 0 if it exceeds 255


def sender():
    max_fragment_size = 1024
    global end_connection
    while not end_connection:
        try:
            message = input("Zadajte správu na odoslanie: ")
            if message == "/end":
                send_end_message()
                end_connection = True
                break

            if message[:4] == "/max":
                max_fragment_size = int(message[4:])
                print(f"Fragment size SET to {max_fragment_size}")
                continue

            send_message(message, max_fragment_size)  # Použije fragmentáciu
        except EOFError:
            end_connection = True
            break

def send_end_message():
    msg_type = 7
    header = create_header(msg_type, 0, 0, 0, 1, 1, b"")
    udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))


def send_message(message, max_fragment_size):
    print("[Sending message] idem posiealt fragmentovanau spravu xd")
    global msg_id  # Increment msg_id for each new message
    header_size = 8  # Veľkosť hlavičky
    max_payload_size = max_fragment_size

    msg_id = (msg_id + 1) % 256  # Cyklovanie ID správy (0-255)

    # Rozdelenie správy na fragmenty
    fragments = [message[i:i + max_payload_size] for i in range(0, len(message), max_payload_size)]
    total_fragments = len(fragments)

    for current_fragment, fragment_data in enumerate(fragments, start=1):
        print("[Sending fragment] ...")
        msg_type = 0b0110  # Typ správy (data)
        flags = 0b0000
        length = len(fragment_data) + header_size
        header = create_header(msg_type, flags, length, msg_id, total_fragments, current_fragment, fragment_data.encode("utf-8"))

        # Odoslanie fragmentu
        udp_socket.sendto(header, (REMOTE_IP, REMOTE_PORT))
        print(f"[Odoslaný fragment {current_fragment}/{total_fragments}]: {fragment_data}")


# def send_message(message):
#     msg_type = 0b0110
#     header = create_header(msg_type, 0, len(message), 0, 1, 1, message.encode())
#     udp_socket.sendto(header + message.encode(), (REMOTE_IP, REMOTE_PORT))


role = 0
def main():
    global role

    the_handshake = handshake()
    if the_handshake:
        print("ideme dalej xd")
    else:
        print("nejdeme dalej xd")
        return


    if LOCAL_PORT < REMOTE_PORT:
        print("som L")
        role = 0
    else:
        print("som W")
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