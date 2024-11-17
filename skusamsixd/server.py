import socket


# Funkcia na spracovanie prijatého fragmentu
def process_fragment(data):
    # Extrahovanie hlavičky a payloadu
    header = data[:4]  # Predpokladáme, že hlavička má 4 bajty
    payload = data[4:]  # Zvyšok je payload (dáta)

    total_fragments, fragment_id = header[:2], header[2:]

    # Vytlačíme informácie o fragmentoch
    print(f"Fragment {fragment_id}/{total_fragments}: {payload.decode()}")


# Nastavenie UDP servera
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('localhost', 12345))

print("Server beží a čaká na fragmenty...")

# Prijímanie fragmentov
while True:
    data, addr = server_socket.recvfrom(1024)  # Prijíma max. 1024 bajtov
    process_fragment(data)
