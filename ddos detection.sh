#!/bin/bash

# Configuration
THRESHOLD=100              # Number of connections to trigger an alert
MONITOR_TIME=60            # Time window in seconds to monitor traffic
INTERFACE="eth0"           # Network interface to monitor (change as needed)
LOG_FILE="ddos_detection.log"  # Log file for alerts

# Initialize log file
echo "DDoS Detection Log" > "$LOG_FILE"
echo "Monitoring on interface: $INTERFACE" >> "$LOG_FILE"
echo "Alert threshold: $THRESHOLD connections" >> "$LOG_FILE"
echo "Monitoring every $MONITOR_TIME seconds" >> "$LOG_FILE"

# Function to monitor DDoS attacks
monitor_ddos() {
    echo "Starting to monitor for potential DDoS attacks on interface: $INTERFACE"

    # Capture TCP packets, extract source IPs, and count connections
    while true; do
        # Use tcpdump to capture packets and process them
        tcpdump -n -i "$INTERFACE" tcp -c 1000 2>/dev/null | \
        awk '{print $3}' | cut -d '.' -f 1-4 | sort | uniq -c | \
        while read count ip; do
            if [ "$count" -gt "$THRESHOLD" ]; then
                alert_message="[ALERT] Possible DDoS attack from IP: $ip with $count connections."
                echo "$alert_message"
                echo "$(date) - $alert_message" >> "$LOG_FILE"
            fi
        done
        
        # Wait before the next monitoring cycle
        sleep "$MONITOR_TIME"
    done
}

# Function to check if tcpdump is installed
check_dependencies() {
    if ! command -v tcpdump &> /dev/null; then
        echo "Error: tcpdump is not installed. Please install it and try again."
        exit 1
    fi
}

# Main script execution
check_dependencies
monitor_ddos
