
import os
import re
import sys

def check_package(package):
    return os.system(f"which {package} > /dev/null 2>&1") == 0

def is_valid_ip(ip):
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    return pattern.match(ip) is not None

def main(target):
    # Verificar si la dirección IP es válida
    if not is_valid_ip(target):
        print("[ERROR] La dirección IP proporcionada no es válida.")
        sys.exit(1)
    
    # Verificar si Nmap está instalado
    if not check_package("nmap"):
        print("[ERROR] Nmap no está instalado. Instálelo y vuelva a intentarlo.")
        sys.exit(1)
    
    # Verificar si OWASP ZAP está instalado
    if not check_package("zap-cli"):
        print("[ERROR] OWASP ZAP no está instalado. Instálelo y vuelva a intentarlo.")
        sys.exit(1)
    
    # Verificar si Metasploit está instalado
    if not check_package("msfconsole"):
        print("[ERROR] Metasploit no está instalado. Instálelo y vuelva a intentarlo.")
        sys.exit(1)
    
    # Abrir archivo para guardar resultados
    with open("resultados.txt", "w") as f:
        # Ejecutar Nmap para escanear los puertos
        print("[*] Escaneando puertos con Nmap...")
        result = os.popen(f"nmap {target}").read()
        
        # Escribir resultados en archivo
        f.write("[*] Resultados del escaneo de puertos:\n\n")
        f.write(result)
        
        # Ejecutar OWASP ZAP para explorar vulnerabilidades
        print("[*] Explorando vulnerabilidades con OWASP ZAP...")
result = os.popen(f"zap-cli quick-scan --start-options '-config api.addrs.addr.name={target} -config api.addrs.addr.regex=false'").read()

Escribir resultados en archivo

f.write("[*] Resultados de la exploración de vulnerabilidades:\n\n")
f.write(result)

Ejecutar Metasploit para explorar vulnerabilidades

print("[*] Explorando vulnerabilidades con Metasploit...")
result = os.popen(f"msfconsole -x 'use auxiliary/scanner/portscan/tcp; set rhosts {target}; run; exit'").read()

Escribir resultados en archivo

f.write("[*] Resultados de la exploración de vulnerabilidades con Metasploit:\n\n")
f.write(result)

Cerrar archivo

f.close()

Mensaje de éxito

print("[*] Análisis de seguridad completado.")
sys.exit(0)
