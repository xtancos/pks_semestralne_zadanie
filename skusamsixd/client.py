import socket

# Nastavenie UDP klienta
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('localhost', 12345)  # IP a port servera

# Textová správa, ktorú chceme odoslať
message = "Toto je veľmi dlhá správa, ktorá bude rozdelená do viacerých fragmentov."

# Parametre fragmentácie
fragment_size = 16  # Max. veľkosť dát v jednom fragmente (bez hlavičky)
total_fragments = (len(message) // fragment_size) + 1

# Rozdelenie správy na fragmenty
for fragment_id in range(total_fragments):
    # Vytváranie hlavičky (2 bajty pre total_fragments, 2 bajty pre fragment_id)
    header = f"{total_fragments:02d}{fragment_id:02d}".encode()  # Formátovanie na 4 bajty (2 pre počet fragmentov a 2 pre fragment_id)

    # Delenie správy na fragmenty
    start = fragment_id * fragment_size
    end = start + fragment_size
    payload = message[start:end].encode()

    # Poslanie fragmentu (hlavička + payload)
    fragment = header + payload
    client_socket.sendto(fragment, server_address)
    print(f"Fragment {fragment_id + 1}/{total_fragments} odoslaný.")
