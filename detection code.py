from scapy.all import *
from collections import defaultdict
import time
import logging

# Configuration
THRESHOLD = 100  # Number of connections to trigger an alert
MONITOR_TIME = 60  # Time window in seconds to monitor traffic
LOG_FILE = "ddos_detection.log"  # Log file for alerts
INTERFACE = "eth0"  # Network interface to monitor (change as needed)

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Dictionary to hold connection counts
connection_counts = defaultdict(int)

def packet_handler(packet):
    """Handles incoming packets and counts TCP connections."""
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        connection_counts[src_ip] += 1

def reset_counts():
    """Resets connection counts and logs any potential DDoS activity."""
    for ip, count in list(connection_counts.items()):
        if count > THRESHOLD:
            alert_message = f"[ALERT] Possible DDoS attack from IP: {ip} with {count} connections."
            print(alert_message)
            logging.info(alert_message)
    connection_counts.clear()

def detect_ddos():
    """Starts sniffing packets on the specified interface."""
    print("Starting to monitor for potential DDoS attacks on interface:", INTERFACE)
    sniff(prn=packet_handler, iface=INTERFACE, filter="tcp", store=0)

if __name__ == "__main__":
    try:
        # Start the packet sniffing in a separate thread
        import threading
        sniff_thread = threading.Thread(target=detect_ddos)
        sniff_thread.daemon = True
        sniff_thread.start()

        while True:
            time.sleep(MONITOR_TIME)
            reset_counts()
    except KeyboardInterrupt:
        print("Stopping the DDoS detection.")
