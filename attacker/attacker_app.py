from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import requests
import threading
import time
from datetime import datetime
import random
import socket
from packet_generator import PacketGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'attacker_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Target Configuration (Defaults)
target_config = {
    'url': "http://localhost:5000/api/inject",
    'ip': "192.168.1.10",
    'port': 80
}

# Initialize generator without needing a model file
generator = PacketGenerator()

# Attack metadata for routes
ATTACK_TYPES = {
    'portscan': {'id': 'PortScan', 'name': 'Port Discovery', 'desc': 'Probe target IP for open socket interfaces.'},
    'bruteforce': {'id': 'BruteForce', 'name': 'Brute Force', 'desc': 'Automated credential guessing.'},
    'bot': {'id': 'Bot', 'name': 'Botnet C&C', 'desc': 'Communication with malicious control servers.'},
    'infiltration': {'id': 'Infiltration', 'name': 'Network Infiltration', 'desc': 'Unauthorized lateral movement.'},
    'dos': {'id': 'DoS', 'name': 'DoS Flood', 'desc': 'Resource exhaustion attack.'},
    'webattack': {'id': 'WebAttack', 'name': 'Web Exploitation', 'desc': 'XSS, SQLi, and web vulnerabilities.'}
}

attacking = False
attack_thread = None
attack_stats = {
    'sent': 0,
    'blocked': 0,
    'detected': 0,
    'pps': 0,
    'last_sent_count': 0
}

def attack_loop(attack_type, intensity, config):
    global attacking, attack_stats
    
    print(f"🚀 Starting {attack_type} attack on {config['url']}")
    print(f"📍 Target: {config['ip']}:{config['port']} | Intensity: {intensity} pkts/sec")
    
    delay = 1.0 / intensity
    last_tick = time.time()
    last_pps_tick = time.time()
    
    while attacking:
        # Generate a packet
        packet = generator.generate_specific_attack(attack_type)
        
        # Override target details in the packet
        packet['dst_ip'] = config['ip']
        packet['dst_port'] = int(config['port'])
        
        # Increment immediately so UI captures the intent
        attack_stats['sent'] += 1
        
        try:
            # Send to defender
            response = requests.post(config['url'], json=packet, timeout=1)
            
            if response.status_code == 200:
                result = response.json().get('result', {})
                if result.get('is_attack'):
                    attack_stats['detected'] += 1
                if result.get('blocked'):
                    attack_stats['blocked'] += 1
        except Exception as e:
            pass # Suppress network errors from breaking the loop
            
        # UI & Log updating Logic (throttle to 10 FPS for UI and 1 FPS for logs)
        now = time.time()
        
        # Fast UI update for stats (10 times a second max)
        if now - last_tick >= 0.1:
            last_tick = now  # always reset so we fire at ~10 FPS
            
            # Calculate PPS once a second
            current_time = time.time()
            if current_time - last_pps_tick >= 1.0:
                attack_stats['pps'] = attack_stats['sent'] - attack_stats['last_sent_count']
                attack_stats['last_sent_count'] = attack_stats['sent']
                last_pps_tick = current_time
                
                # Emit log entry once a second to prevent DOM bloat
                socketio.emit('attack_log', {
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'msg': f"INJECTED BATCH ({attack_stats['pps']} pkts): {attack_type} -> {config['ip']}:{config['port']}"
                })
            
            socketio.emit('attack_update', attack_stats)
            
        time.sleep(delay)
    
    attack_stats['pps'] = 0
    socketio.emit('attack_update', attack_stats)
    print("🛑 Attack stopped")

def scan_loop(target_ip, port_range, config):
    global attacking, attack_stats
    
    try:
        start_port, end_port = map(int, port_range.split('-'))
    except:
        start_port, end_port = 1, 1024
        
    print(f"🔍 Starting Port Scan on {target_ip} [{start_port}-{end_port}]")
    attack_stats['open_ports'] = []
    
    last_tick = time.time()
    last_ui_tick = time.time()
    
    for port in range(start_port, end_port + 1):
        if not attacking:
            break
            
        # 1. Real socket check
        is_open = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.05) # Fast scan
                if s.connect_ex((target_ip, port)) == 0:
                    is_open = True
        except:
            pass
            
        # 2. Simulated packet to IDPS (to trigger detection)
        packet = generator.generate_specific_attack('PortScan')
        packet['dst_ip'] = target_ip
        packet['dst_port'] = port
        
        attack_stats['sent'] += 1
        try:
            requests.post(config['url'], json=packet, timeout=0.05)
        except:
            pass
            
        # 3. Handle results
        if is_open:
            if port not in attack_stats['open_ports']:
                attack_stats['open_ports'].append(port)
            socketio.emit('attack_log', {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'msg': f"FOUND OPEN PORT: {port}",
                'type': 'success'
            })
            attack_stats['detected'] = len(attack_stats['open_ports'])
            
        now = time.time()
        # Calulate PPS every second
        if now - last_tick >= 1.0:
            attack_stats['pps'] = attack_stats['sent'] - attack_stats['last_sent_count']
            attack_stats['last_sent_count'] = attack_stats['sent']
            last_tick = now
            
        # Throttle UI updates to 10 FPS
        if now - last_ui_tick >= 0.1:
            socketio.emit('attack_update', attack_stats)
            last_ui_tick = now
            
        time.sleep(0.01) # Small throttle

    print("🛑 Scan complete")
    attacking = False
    socketio.emit('scan_complete', {'success': True})

@app.route('/')
def index():
    return render_template('attacker.html', attacks=ATTACK_TYPES)

@app.route('/attack/<attack_name>')
def attack_page(attack_name):
    if attack_name not in ATTACK_TYPES:
        return "Attack type not found", 404
    return render_template('attack_page.html', 
                           attack=ATTACK_TYPES[attack_name], 
                           attack_key=attack_name,
                           attacks=ATTACK_TYPES)

@app.route('/api/attack/start', methods=['POST'])
def start_attack():
    global attacking, attack_thread
    
    if attacking:
        return jsonify({'success': False, 'message': 'Attack already in progress'})
        
    data = request.json
    attack_type = data.get('type', 'PortScan')
    intensity = int(data.get('intensity', 5))
    target_ip = data.get('targetIp', '192.168.1.10')
    
    config = {
        'url': data.get('targetUrl', 'http://localhost:5000/api/inject'),
        'ip': target_ip,
        'port': data.get('targetPort', 80)
    }
    
    attacking = True
    
    if attack_type == 'PortScan':
        port_range = data.get('portRange', '1-1024')
        attack_thread = threading.Thread(target=scan_loop, args=(target_ip, port_range, config), daemon=True)
    else:
        attack_thread = threading.Thread(target=attack_loop, args=(attack_type, intensity, config), daemon=True)
        
    attack_thread.start()
    
    return jsonify({'success': True, 'message': f'{attack_type} attack started'})

@app.route('/api/attack/stop', methods=['POST'])
def stop_attack():
    global attacking
    attacking = False
    return jsonify({'success': True, 'message': 'Attack stopped'})

@app.route('/api/stats/reset', methods=['POST'])
def reset_stats():
    global attack_stats
    attack_stats = {
        'sent': 0, 
        'blocked': 0, 
        'detected': 0, 
        'pps': 0, 
        'last_sent_count': 0, 
        'open_ports': []
    }
    return jsonify({'success': True})

if __name__ == '__main__':
    print("="*70)
    print("Attacker System Dashboard - Standalone Mode")
    print("="*70)
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
