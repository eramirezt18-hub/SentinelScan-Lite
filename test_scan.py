import socket

objetivo = "127.0.0.1"  # Tu propia computadora
puertos = [80, 443, 3306, 8080]

print(f"Escaneando {objetivo}...")

for puerto in puertos:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    resultado = s.connect_ex((objetivo, puerto))
    if resultado == 0:
        print(f"Puerto {puerto}: ABIERTO")
    else:
        print(f"Puerto {puerto}: cerrado")
    s.close()