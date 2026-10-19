import subprocess
import platform

def escanear_red_real():
    print("🔍 Iniciando escaneo de la red local (Leyendo tabla ARP)...")
    
    # Dependiendo del sistema operativo, el comando cambia
    sistema = platform.system()
    
    if sistema == "Windows":
        comando = "arp -a"
    else:
        comando = "arp -a" # En Mac/Linux también funciona

    try:
        # Ejecutamos el comando en la terminal y capturamos el resultado
        resultado = subprocess.check_output(comando, shell=True).decode('utf-8', errors='ignore')
        
        print("\n--- DISPOSITIVOS ENCONTRADOS EN LA RED ---")
        # Filtramos la salida para mostrar solo las IPs y MACs
        lineas = resultado.split('\n')
        for linea in lineas:
            if "192.168." in linea or "10.0." in linea or "172." in linea:
                # Limpiamos un poco el texto para que se vea bonito
                print(linea.strip())
                
    except Exception as e:
        print(f"Error al escanear: {e}")

escanear_red_real()