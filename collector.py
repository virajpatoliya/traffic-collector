import os
import json
import requests
from dotenv import load_dotenv
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

# Load environment variables
load_dotenv()
API_URL = os.getenv("API_URL")

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        proto = "UNKNOWN"
        sport = dport = None

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        payload = {
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "source_port": sport,
            "destination_port": dport,
            "protocol": proto,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(API_URL, headers=headers, json=payload)
            print(f"Sent: {json.dumps(payload)} | Status: {response.status_code}")
        except Exception as e:
            print(f"Failed to send packet data: {e}")

def main():
    print("Starting packet capture...")
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
