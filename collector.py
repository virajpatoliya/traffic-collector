import os
import json
import requests
from dotenv import load_dotenv
from datetime import datetime
from scapy.all import sniff, IP, ICMP, DNS, UDP, TCP, DNSQR
import logging

# --- Load environment variables ---
load_dotenv()
API_URL = os.getenv("API_URL")
if not API_URL:
    raise EnvironmentError("Missing required environment variable: API_URL")


# --- Constants ---
HEADERS = {'Content-Type': 'application/json'}

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("traffic.log"),
        logging.StreamHandler()
    ]
)

# --- Packet Handler ---
def process_packet(packet):
    if IP not in packet:
        return

    ip_layer = packet[IP]
    proto = "UNKNOWN"
    sport = dport = None
    extra_fields = {}

    if ICMP in packet:
        proto = "ICMP"
        icmp_layer = packet[ICMP]
        extra_fields = {
            "icmp_type": icmp_layer.type,
            "icmp_code": icmp_layer.code
        }

    elif DNS in packet:
        proto = "DNS"

        # Extract source and destination ports from UDP or TCP
        if UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        dns_layer = packet[DNS]
        extra_fields = {
            "dns_qr": dns_layer.qr,
            "dns_opcode": dns_layer.opcode,
            "dns_rcode": dns_layer.rcode
        }

        # Add queried domain if it's a query and has question section
        if dns_layer.qr == 0 and dns_layer.qdcount > 0 and DNSQR in dns_layer:
            extra_fields["dns_qname"] = dns_layer[DNSQR].qname.decode(errors="ignore")

    if proto == "UNKNOWN":
        return

    payload = {
        "source_ip": ip_layer.src,
        "destination_ip": ip_layer.dst,
        "source_port": sport,
        "destination_port": dport,
        "protocol": proto,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        **extra_fields
    }

    logging.info(f"Captured packet: {payload}")

    try:
        response = requests.post(API_URL, headers=HEADERS, json=payload, timeout=5)
        logging.info(f"Sent to API | Status: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Failed to send packet data: {e}")

# --- Sniffer Entry Point ---
def main():
    logging.info("Starting packet capture on all interfaces...")
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
