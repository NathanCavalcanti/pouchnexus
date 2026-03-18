import time
import requests
import threading
import socket
from scapy.all import sniff, TCP, IP
from datetime import datetime
import sys

# --- CONFIGURACIÓN ---
# IP de la máquina Windows donde corre la API
SOC_WIN_IP = "192.168.100.2"
ENDPOINT = f"http://{SOC_WIN_IP}:8000/api/v1/ingest/generic"

# Puertos a vigilar (Simulan servicios reales)
PORTS = {
    2222: "SSH",
    2223: "Telnet",
    3306: "MySQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}
MONITORED_PORTS = list(PORTS.keys())

# Anti-Flood mejorado: (IP, Puerto) -> Último reporte
reported_cache = {}
THROTTLE_TIME = 60


def send_to_soc(attacker_ip, port, flags_str):
    now_ts = time.time()
    # Identificador único para no repetir el mismo reporte en 60s
    key = f"{attacker_ip}:{port}"

    if key in reported_cache and (now_ts - reported_cache[key] < THROTTLE_TIME):
        return

    service = PORTS.get(port, "Unknown")

    # Mapeo de tipo de ataque según banderas TCP
    attack_desc = "Escaneo de Red"
    if "S" in flags_str and "A" not in flags_str:
        attack_desc = "TCP SYN Scan (Stealth)"
    elif flags_str == "A":
        attack_desc = "TCP ACK Scan (Firewall Probe)"
    elif "R" in flags_str:
        attack_desc = "TCP RST Probe"
    elif "P" in flags_str:
        attack_desc = "Data Push (PSH) Attempt"
    elif "F" in flags_str:
        attack_desc = "FIN Scan (Stealth)"

    msg = f"🛡️ TRÁFICO SOSPECHOSO: [{flags_str}] detectado desde {attacker_ip} al puerto {port} ({service})."

    payload = {
        "text": msg,
        "source_name": "honeypot-ubuntu",
        "severity": "medium",
        "attack_type": attack_desc,
        "skip_analysis": True,  # No gastar IA en sondeos de red, solo enriquecimiento de IP
    }

    try:
        r = requests.post(ENDPOINT, json=payload, timeout=3)
        reported_cache[key] = now_ts
        print(
            f"[{datetime.now().strftime('%H:%M:%S')}] ✅ SOC: {attacker_ip} -> {port} [{flags_str}] ({attack_desc}) | Status: {r.status_code}"
        )
    except Exception as e:
        print(f"[!] Error enviando al SOC: {e}")


# --- SNIFFER MULTI-FLAG ---
def packet_callback(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        # Solo miramos tráfico ENTRANTE a nuestros puertos vigilados
        if pkt[TCP].dport in MONITORED_PORTS:
            flags = pkt[TCP].flags
            send_to_soc(pkt[IP].src, pkt[TCP].dport, str(flags))


def start_sniffer():
    print("[*] Sniffer iniciado en modo promiscuo...")
    sniff(filter="tcp", prn=packet_callback, store=0)


# --- LISTENER DE PUERTOS (Para que los puertos parezcan ABIERTOS) ---
def port_listener(port, service):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        while True:
            client, addr = s.accept()
            try:
                client.send(b"Access Denied. Internal Monitoring Active.\n")
                client.close()
            except Exception:
                pass
    except Exception as e:
        print(f"[!] Error en listener puerto {port}: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        SOC_WIN_IP = sys.argv[1]
        ENDPOINT = f"http://{SOC_WIN_IP}:8000/api/v1/ingest/generic"

    print("=== HONEYPOT V8.1 (MULTI-FLAG IDS MODE) ===")
    print(f"[*] Detectando SYN, ACK, RST, PSH, FIN en: {MONITORED_PORTS}")
    print(f"[*] Reportando a: {ENDPOINT}")

    # Abrir listeners en segundo plano para tentar a los atacantes
    for p, s in PORTS.items():
        threading.Thread(target=port_listener, args=(p, s), daemon=True).start()

    try:
        start_sniffer()
    except PermissionError:
        print("\n[ERROR] ¡Debes usar SUDO para analizar banderas TCP con Scapy!")
    except KeyboardInterrupt:
        print("\n[!] Apagando sensor...")
