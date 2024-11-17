import struct

# Parametre hlavičky
type_size = 1  # 1 byte
flag_size = 1  # 1 byte
length_size = 2  # 2 bytes
id_size = 1  # 1 byte
f_all_size = 1  # 2 bytes
f_act_size = 1  # 2 bytes
crc_size = 2  # 2 bytes
data_length = size_of_fragment

def create_fragment_format(type_size, flag_size, length_size, id_size, f_all_size, f_act_size, crc_size, data_size):
    fragment_format = f"{type_size}B {flag_size}B {length_size}H {id_size}B {f_all_size}H {f_act_size}H {crc_size}H {data_size}s"
    return fragment_format



# Vytvorenie formátu
format_string = create_fragment_format(type_size, length_size, id_size, f_all_size, f_act_size, crc_size, flag_size, data_length)
print("Fragment format:", format_string)

# Výstup bude napríklad:
# Fragment format: 1B 2H 1B 2H 2H 2H 1B 100s





def create_header(type, lenght, id, f_all, f_act, crc, flag, data):
    fragment_format = f"{type}{lenght}{id}{f_all}{f_act}{crc}{flag}{data}"



# Parametre
message_type = 0b0101  # Typ správy (4 bity)
data_length = 5        # Dĺžka dát v bajtoch
data = b'Hello'        # Dáta

# Formát pre struct: 1 bajt pre typ správy (4 bity), 2 bajty pre dĺžku dát, a dáta ako reťazec.
# "B" = unsigned char (1 byte), "H" = unsigned short (2 bytes)
# Dáta budú kódované ako binárny reťazec.
fragment_format = 'B H {}s'.format(data_length)

# Inicializácia fragmentu
fragment = struct.pack(fragment_format, message_type, data_length, data)

# Výpis binárnych dát fragmentu
print("Vytvorený fragment:", fragment)

# Dekódovanie fragmentu späť na pôvodné hodnoty
unpacked_data = struct.unpack(fragment_format, fragment)
print("Dekódované dáta:", unpacked_data)

# Extrahovanie hodnôt
unpacked_message_type, unpacked_data_length, unpacked_data_content = unpacked_data
print(f"Typ správy: {unpacked_message_type}, Dĺžka dát: {unpacked_data_length}, Dáta: {unpacked_data_content.decode()}")
