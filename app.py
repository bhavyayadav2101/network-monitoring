from flask import Flask, render_template, jsonify
import subprocess
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('devices.html')

@app.route('/devices_page')
def devices_page():
    return render_template('devices.html')

@app.route('/network_page')
def network_page():
    return render_template('network.html')

@app.route('/security_page')
def security_page():
    return render_template('security.html')

@app.route('/devices')
def devices():
    connected_devices = []

    # List devices connected via ARP
    arp_devices = get_arp_devices()
    for device in arp_devices:
        connected_devices.append({
            'type': 'ARP Device',
            'ip_address': device['ip_address'],
            'mac_address': device['mac_address'],
            'name': device['name'] if 'name' in device else 'Unknown'
        })

    # List WiFi hotspots
    wifi_hotspots = get_wifi_hotspots()
    for hotspot in wifi_hotspots:
        connected_devices.append({
            'type': 'WiFi Hotspot',
            'ssid': hotspot['ssid'],
            'bssid': hotspot['bssid'],
            'name': hotspot['name'] if 'name' in hotspot else 'Unknown'
        })

    # Check router connection
    router_connected = check_router_connection()
    if router_connected:
        connected_devices.append({
            'type': 'Router',
            'name': 'Router'
        })

    # Get connected Wi-Fi network name (SSID)
    connected_wifi = get_connected_wifi()
    if connected_wifi:
        connected_devices.append({
            'type': 'Connected WiFi',
            'ssid': connected_wifi,
            'name': connected_wifi
        })

    return jsonify(connected_devices=connected_devices)

@app.route('/network')
def network():
    # Placeholder data for demonstration
    network_data = {
        'isp': 'Example ISP',
        'external_ip': '192.0.2.1',
        'gateway_ip': '192.0.2.254',
        'router_model': 'Example Router Model',
        'firmware_version': '1.0.0',
        'download_speed': '50',
        'upload_speed': '10'
    }
    return jsonify(network_data)

@app.route('/security')
def security():
    # Placeholder data for demonstration
    security_data = {
        'overall_status': 'Secure',
        'last_scan': '2024-07-21',
        'firewall_status': 'Active',
        'vulnerabilities_found': 0
    }
    return jsonify(security_data)

def get_arp_devices():
    command = "arp -a"
    result = subprocess.check_output(command, shell=True, text=True)
    devices = parse_arp_devices(result)
    return devices

def parse_arp_devices(result):
    devices = []
    lines = result.splitlines()
    for line in lines:
        if re.match(r'^\s*\d+\.\d+\.\d+\.\d+\s+', line):
            parts = line.split()
            ip_address = parts[0]
            mac_address = parts[1]
            devices.append({'ip_address': ip_address, 'mac_address': mac_address})
    return devices

def get_wifi_hotspots():
    command = "netsh wlan show networks mode=Bssid"
    result = subprocess.check_output(command, shell=True, text=True)
    hotspots = parse_wifi_hotspots(result)
    return hotspots

def parse_wifi_hotspots(result):
    hotspots = []
    lines = result.splitlines()
    ssid = ""
    bssid = ""
    for line in lines:
        if "SSID" in line:
            ssid = line.split(":")[1].strip()
        elif "BSSID" in line:
            bssid = line.split(":")[1].strip()
            hotspots.append({'ssid': ssid, 'bssid': bssid})
            ssid = ""  # Reset ssid for next network
    return hotspots

def check_router_connection():
    command = "ipconfig"
    result = subprocess.check_output(command, shell=True, text=True)
    if "Default Gateway" in result:
        return True
    return False

def get_connected_wifi():
    command = "netsh wlan show interfaces"
    result = subprocess.check_output(command, shell=True, text=True)
    lines = result.splitlines()
    ssid = ""
    for line in lines:
        if "SSID" in line:
            ssid = line.split(":")[1].strip()
            break
    return ssid

if __name__ == '__main__':
    app.run(debug=True)
