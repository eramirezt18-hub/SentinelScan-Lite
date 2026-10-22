import time
import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
from datetime import datetime
from reportlab.pdfgen import canvas as pdfcanvas
import os
from PIL import Image, ImageTk

# --- Clasificación de Riesgo ---
riesgos = {
    21: "CRÍTICO (FTP sin cifrar)",
    22: "MEDIO (SSH)",
    23: "CRÍTICO (Telnet)",
    25: "MEDIO (SMTP)",
    53: "BAJO (DNS)",
    80: "BAJO (HTTP sin cifrar)",
    110: "MEDIO (POP3)",
    143: "MEDIO (IMAP)",
    443: "BAJO (HTTPS seguro)",
    3306: "CRÍTICO (Base de datos expuesta)",
    3389: "CRÍTICO (Escritorio remoto)",
    8080: "MEDIO (Proxy/HTTP alternativo)"
}

def escanear():
    objetivo = entrada.get().strip()
    if not objetivo:
        messagebox.showwarning("Aviso", "Ingresa una IP o dominio")
        return
    
    btn_escanear.config(state=tk.DISABLED)
    barra['value'] = 0
    resultado_texto.delete(1.0, tk.END)
    resultado_texto.insert(tk.END, f"[*] Iniciando escaneo contra: {objetivo}\n")
    resultado_texto.insert(tk.END, "[-] Analizando puertos remotos...\n\n")
    
    puertos = list(riesgos.keys())
    abiertos = []
    
    for i, puerto in enumerate(puertos):
        time.sleep(0.1)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            resultado = s.connect_ex((objetivo, puerto))
            
            if resultado == 0:
                abiertos.append(puerto)
                nivel = riesgos.get(puerto, "DESCONOCIDO")
                # Etiqueta de color en la consola de texto (simulado con texto por ahora)
                resultado_texto.insert(tk.END, f"[+] Puerto {puerto} ABIERTO -> RIESGO: {nivel}\n")
                resultado_texto.see(tk.END)
            s.close()
        except Exception:
            pass
        
        # Actualizar barra
        barra['value'] = ((i + 1) / len(puertos)) * 100
        ventana.update_idletasks()
    
    if abiertos:
        # Nombre del reporte
        nombre_pdf = f"Reporte_{objetivo.replace('.', '_').replace('/', '_')}.pdf"
        generar_pdf(objetivo, abiertos, nombre_pdf)
        resultado_texto.insert(tk.END, f"\n[!] ¡ESCANEO COMPLETADO!\n")
        resultado_texto.insert(tk.END, f"[!] Se encontraron {len(abiertos)} puertos abiertos.\n")
        resultado_texto.insert(tk.END, f"[!] Reporte generado exitosamente: {nombre_pdf}\n")
    else:
        resultado_texto.insert(tk.END, "\n[✓] No se encontraron puertos abiertos en el escaneo.\n")
        
    btn_escanear.config(state=tk.NORMAL)

def generar_pdf(objetivo, puertos_abiertos, nombre_archivo):
    c = pdfcanvas.Canvas(nombre_archivo)
    
    # Encabezado estilo Sentinel
    c.setFillColorRGB(0, 0.8, 1) # Color Cyan
    c.setFont("Helvetica-Bold", 22)
    c.drawString(50, 800, "SENTINEL CYBERFORCE")
    
    c.setFillColorRGB(0, 0, 0) # Negro
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, 775, "Reporte de Escaneo de Vulnerabilidades - SentinelScan Lite")
    c.setFont("Helvetica", 11)
    c.drawString(50, 755, f"Objetivo Evaluado: {objetivo}")
    c.drawString(50, 740, f"Fecha y Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.line(50, 730, 550, 730) # Línea divisoria
    
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, 700, "Hallazgos Encontrados:")
    
    y = 670
    c.setFont("Helvetica", 11)
    for p in puertos_abiertos:
        nivel = riesgos.get(p, "DESCONOCIDO")
        c.drawString(70, y, f"• Puerto {p} - Estado: ABIERTO - Nivel de Riesgo: {nivel}")
        y -= 25 
    
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(50, 100, "Documento generado automáticamente por SentinelScan Lite.")
    c.drawString(50, 85, "SENTINEL CYBERFORCE - 'Tu mayor vulnerabilidad es no conocernos'")
    
    c.save()

# --- Interfaz Gráfica ---
ventana = tk.Tk()
ventana.title("SentinelScan Lite - SENTINEL CYBERFORCE")
ventana.geometry("750x600")
ventana.configure(bg="#0a0f1e") 

# Título y Subtítulo
try:
    img_original = Image.open("LogoSentinelScan.png")  # tu imagen (png, jpg, etc.)
    img_redimensionada = img_original.resize((140, 140), Image.Resampling.LANCZOS)  # ajusta tamaño
    logo_img = ImageTk.PhotoImage(img_redimensionada)
except Exception as e:
    print(f"No se pudo cargar el logo: {e}")
    logo_img = None

frame_header = tk.Frame(ventana, bg="#0a0f1e")
frame_header.pack(pady=10)

if logo_img:
    tk.Label(frame_header, image=logo_img, bg="#0a0f1e").pack(side=tk.LEFT, padx=10)

tk.Label(
    frame_header,
    text="Sentinel Scan",
    font=("Helvetica", 24, "bold"),
    fg="#00d4ff",
    bg="#0a0f1e"
).pack(side=tk.LEFT, padx=5)
tk.Label(ventana, text="Módulo de Detección de Puertos Abiertos", font=("Helvetica", 12), fg="white", bg="#0a0f1e").pack()

# Marco de búsqueda
frame_busqueda = tk.Frame(ventana, bg="#0a0f1e")
frame_busqueda.pack(pady=20)

tk.Label(frame_busqueda, text="Objetivo (IP o Dominio):", fg="white", bg="#0a0f1e", font=("Helvetica", 11, "bold")).pack(side=tk.LEFT, padx=5)

entrada = tk.Entry(frame_busqueda, width=35, font=("Helvetica", 11), bg="#1a233a", fg="white", insertbackground="white")
entrada.pack(side=tk.LEFT, padx=5)
entrada.insert(0, "127.0.0.1") 

btn_escanear = tk.Button(frame_busqueda, text="▶ Iniciar Escaneo", command=lambda: threading.Thread(target=escanear).start(), bg="#00d4ff", fg="black", font=("Helvetica", 10, "bold"), relief=tk.FLAT, padx=15, pady=5, cursor="hand2")
btn_escanear.pack(side=tk.LEFT, padx=10)

# Barra de progreso (Estilo personalizado)
style = ttk.Style()
style.theme_use('default')
style.configure("TProgressbar", thickness=20, troughcolor='#1a233a', background='#00d4ff')

barra = ttk.Progressbar(ventana, length=600, mode='determinate', style="TProgressbar")
barra.pack(pady=10)

# Consola de resultados
tk.Label(ventana, text="Registro de Actividad (Consola):", fg="gray", bg="#0a0f1e", font=("Helvetica", 10)).pack(anchor="w", padx=75)
resultado_texto = tk.Text(ventana, height=15, width=85, bg="black", fg="#00ff00", font=("Consolas", 10), relief=tk.FLAT)
resultado_texto.pack(pady=5, padx=75)

ventana.mainloop()