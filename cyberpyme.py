import tkinter as tk
from tkinter import messagebox
import subprocess
import platform
import threading
import socket
import re

# --- Función para obtener la IP local ---
def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Desconocida"

# --- Función principal de escaneo ---
def procesar_escaneo():
    lista_dispositivos.delete(0, tk.END)
    lbl_estado.config(text="🔍 Analizando dispositivos conectados a la red...", fg="yellow")
    ventana.update()
    
    try:
        limite_str = entrada_limite.get()
        if not limite_str.isdigit():
            messagebox.showerror("Error", "Por favor, ingresa un número válido de dispositivos permitidos.")
            btn_escanear.config(state=tk.NORMAL)
            lbl_estado.config(text="Error en la configuración.", fg="red")
            return
            
        limite_permitido = int(limite_str)
        
        comando = "arp -a"
        resultado = subprocess.check_output(comando, shell=True).decode('utf-8', errors='ignore')
        lineas = resultado.split('\n')
        
        macs_vistas = set() # Aquí guardaremos las MACs para no repetirlas
        dispositivos_validos = 0
        
        # Expresión regular para buscar IPs y MACs válidas
        patron_ip = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F-]{17})')
        
        for linea in lineas:
            match = patron_ip.search(linea)
            if match:
                ip = match.group(1)
                mac = match.group(2).lower()
                
                # Ignorar MACs de Broadcast o Multicast
                if mac == "ff-ff-ff-ff-ff-ff" or ip.endswith(".255"):
                    continue
                
                # FILTRO CLAVE: Si la MAC ya fue contada, la ignoramos
                if mac in macs_vistas:
                    continue
                
                # Si es una IP de red local
                if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                    macs_vistas.add(mac) # Guardamos la MAC para no volver a contarla
                    dispositivos_validos += 1
                    lista_dispositivos.insert(tk.END, f"📱 Dispositivo IP: {ip} | MAC: {mac}")
                    
        # --- Lógica de Alerta con el límite del usuario ---
        if dispositivos_validos > limite_permitido:
            lbl_estado.config(text=f"⚠️ Alerta: ¡{dispositivos_validos} dispositivos detectados! (Límite: {limite_permitido})", fg="#ff4d4d")
            messagebox.showwarning(
                "Alerta de Seguridad - CyberPyme", 
                f"¡Se han detectado {dispositivos_validos} dispositivos únicos en tu red!\n\n"
                f"Tu límite configurado es de {limite_permitido} dispositivos.\n"
                "Revisa la lista para ver si hay algún intruso.\n\n"
                "Recomendación: Cambia tu contraseña del WiFi y revisa la lista."
            )
        else:
            lbl_estado.config(text=f"✅ Red Segura. {dispositivos_validos} dispositivos (Límite: {limite_permitido}).", fg="#00ff00")
            messagebox.showinfo(
                "Red Segura - CyberPyme", 
                f"Se detectaron {dispositivos_validos} dispositivos únicos.\n"
                f"Esto está dentro de tu límite de {limite_permitido}.\n\n"
                "Tu red se encuentra protegida."
            )
            
    except Exception as e:
        lbl_estado.config(text="❌ Error al escanear la red.", fg="red")
        messagebox.showerror("Error", f"No se pudo leer la red: {e}")

def iniciar_escaneo():
    btn_escanear.config(state=tk.DISABLED)
    hilo = threading.Thread(target=procesar_escaneo)
    hilo.start()
    ventana.after(2000, lambda: btn_escanear.config(state=tk.NORMAL) if btn_escanear.winfo_exists() else None)

# --- Interfaz Gráfica ---
ventana = tk.Tk()
ventana.title("CyberPyme - Escudo para tu Pyme")
ventana.geometry("750x600")
ventana.configure(bg="#0a0f1e")

tk.Label(ventana, text="🛡️ CYBERPYME", font=("Helvetica", 24, "bold"), fg="#00d4ff", bg="#0a0f1e").pack(pady=10)
tk.Label(ventana, text="Protección inteligente para tu negocio local", font=("Helvetica", 12), fg="gray", bg="#0a0f1e").pack()

ip_actual = obtener_ip_local()
tk.Label(ventana, text=f"Red actual detectada: {ip_actual}", font=("Helvetica", 10), fg="#8b949e", bg="#0a0f1e").pack(pady=2)

# --- NUEVO: Casilla para el límite de dispositivos ---
frame_config = tk.Frame(ventana, bg="#161b22", bd=1, relief=tk.SOLID)
frame_config.pack(pady=15, padx=50, fill=tk.X)

tk.Label(frame_config, text="⚙️ Configuración de Seguridad:", font=("Helvetica", 10, "bold"), fg="white", bg="#161b22").pack(side=tk.LEFT, padx=10, pady=5)

tk.Label(frame_config, text="Dispositivos permitidos:", font=("Helvetica", 10), fg="gray", bg="#161b22").pack(side=tk.LEFT, padx=5)
entrada_limite = tk.Entry(frame_config, width=5, font=("Helvetica", 10), bg="#0a0f1e", fg="#00d4ff", insertbackground="white")
entrada_limite.insert(0, "2") # Valor por defecto
entrada_limite.pack(side=tk.LEFT, padx=5)

# Botón de escaneo
btn_escanear = tk.Button(
    ventana, 
    text="🔍 Escanear Red WiFi del Negocio", 
    command=iniciar_escaneo, 
    bg="#00d4ff", fg="black", font=("Helvetica", 12, "bold"), relief=tk.FLAT, padx=20, pady=5, cursor="hand2"
)
btn_escanear.pack(pady=5)

lbl_estado = tk.Label(ventana, text="Esperando instrucciones...", font=("Helvetica", 11, "bold"), fg="white", bg="#0a0f1e")
lbl_estado.pack(pady=10)

frame_lista = tk.Frame(ventana, bg="#161b22", bd=1, relief=tk.SOLID)
frame_lista.pack(pady=10, padx=30, fill=tk.BOTH, expand=True)

tk.Label(frame_lista, text="Dispositivos reales detectados en la red:", fg="#00d4ff", bg="#161b22", font=("Helvetica", 10, "bold")).pack(anchor="w", padx=10, pady=5)

scrollbar = tk.Scrollbar(frame_lista)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

lista_dispositivos = tk.Listbox(
    frame_lista, yscrollcommand=scrollbar.set, bg="#0a0f1e", fg="white", font=("Consolas", 10), 
    height=10, selectbackground="#00d4ff", selectforeground="black", borderwidth=0
)
lista_dispositivos.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=5)
scrollbar.config(command=lista_dispositivos.yview)

tk.Label(ventana, text="Sentinel Cyberforce © 2026", font=("Helvetica", 9), fg="gray", bg="#0a0f1e").pack(side=tk.BOTTOM, pady=5)

ventana.mainloop()