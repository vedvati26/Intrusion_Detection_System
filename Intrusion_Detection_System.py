import threading
import queue
import json
from scapy.all import sniff, IP, TCP
from collections import defaultdict
from sklearn.ensemble import IsolationForest
import numpy as np
import logging

# Configure logging for better debugging and visibility
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# PacketCapture class handles network packet capture
class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()  # Queue to hold captured packets
        self.stop_capture = threading.Event()  # Event to signal stopping of packet capture

    # Callback function to process captured packets
    def packet_callback(self, packet):
        if IP in packet and TCP in packet:  # Filter for IP and TCP packets
            self.packet_queue.put(packet)  # Add packet to the queue

    # Start capturing packets on the specified network interface
    def start_capture(self, interface="wlo1"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,  # Callback for each packet
                  store=0,  # Do not store packets in memory
                  stop_filter=lambda _: self.stop_capture.is_set())  # Stop condition

        self.capture_thread = threading.Thread(target=capture_thread)  # Run sniffing in a separate thread
        self.capture_thread.start()

    # Stop packet capture
    def stop(self):
        self.stop_capture.set()  # Signal to stop capture
        self.capture_thread.join()  # Wait for the thread to finish

# TrafficAnalyzer class processes captured packets and extracts features
class TrafficAnalyzer:
    def __init__(self):
        self.packet_data = []  # List to store packet information

    # Process individual packets and extract relevant details
    def process_packet(self, packet):
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        sport = packet[TCP].sport  # Source port
        dport = packet[TCP].dport  # Destination port
        payload_size = len(packet[TCP].payload)  # Payload size
        self.packet_data.append([ip_src, ip_dst, sport, dport, payload_size])

    # Get features from captured packets for anomaly detection
    def get_features(self):
        return np.array([data[4] for data in self.packet_data]).reshape(-1, 1)  # Use payload size as the feature

# DetectionEngine class handles anomaly detection using Isolation Forest
class DetectionEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01)  # Isolation Forest model with contamination rate
        self.trained = False  # Flag to indicate if the model is trained

    # Train the model with extracted features
    def train(self, features):
        self.model.fit(features)  # Fit the model to normal traffic data
        self.trained = True

    # Predict anomalies in the features
    def predict(self, features):
        if not self.trained:
            raise Exception("Model not trained yet.")
        return self.model.predict(features)  # Predict anomalies (-1 indicates anomaly)

# AlertSystem class generates alerts for detected anomalies
class AlertSystem:
    def __init__(self):
        self.alerts = []  # List to store generated alerts

    # Generate and log an alert for a suspicious packet
    def generate_alert(self, packet_info):
        alert = {
            "source_ip": packet_info[0],
            "destination_ip": packet_info[1],
            "source_port": packet_info[2],
            "destination_port": packet_info[3],
            "payload_size": packet_info[4]
        }
        self.alerts.append(alert)  # Add alert to the list
        logging.warning(f"Intrusion detected: {json.dumps(alert)}")  # Log the alert

# IntrusionDetectionSystem integrates all components of the IDS
class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        self.packet_capture = PacketCapture()  # Initialize PacketCapture
        self.traffic_analyzer = TrafficAnalyzer()  # Initialize TrafficAnalyzer
        self.detection_engine = DetectionEngine()  # Initialize DetectionEngine
        self.alert_system = AlertSystem()  # Initialize AlertSystem
        self.interface = interface  # Network interface to monitor

    # Start the IDS
    def start(self):
        logging.info("Starting packet capture...")
        self.packet_capture.start_capture(self.interface)  # Start capturing packets
        try:
            while True:
                # Process packets from the queue
                packet = self.packet_capture.packet_queue.get()
                self.traffic_analyzer.process_packet(packet)  # Analyze packet

                # Once enough packets are captured, perform detection
                if len(self.traffic_analyzer.packet_data) >= 100:
                    features = self.traffic_analyzer.get_features()  # Extract features

                    if not self.detection_engine.trained:
                        logging.info("Training detection model...")
                        self.detection_engine.train(features)  # Train the model
                    else:
                        predictions = self.detection_engine.predict(features)  # Detect anomalies
                        for i, prediction in enumerate(predictions):
                            if prediction == -1:  # Anomaly detected
                                self.alert_system.generate_alert(self.traffic_analyzer.packet_data[i])

                    # Clear processed packet data
                    self.traffic_analyzer.packet_data = []
        except KeyboardInterrupt:
            logging.info("Stopping packet capture...")
            self.packet_capture.stop()  # Stop capturing packets

# Main entry point for the IDS script
if __name__ == "__main__":
    ids = IntrusionDetectionSystem(interface="wlo1")  # Create IDS instance with specified interface
    ids.start()  # Start the IDS

