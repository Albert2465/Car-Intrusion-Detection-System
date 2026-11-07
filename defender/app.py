"""
Complete Flask Web Server with:
- ML Detection
- Manual Rule Creation
- UI Attack Diversity (even if ML only detects DoS)
- Manual IP Blocking
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
from datetime import datetime
from hybrid_detection_system import HybridIDPS
from packet_generator import PacketGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'idps_secret_key_2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
idps = None
generator = None
monitoring_active = False
monitoring_thread = None

# Add near the top with other global variables (after stats, attack_distribution, etc.)
forensic_packets = []  # Store last N packets with full details
MAX_FORENSIC_PACKETS = 1000

# Statistics
stats = {
    'total_packets': 0,
    'benign': 0,
    'attacks': 0,
    'blocked_ips': 0,
    'threat_level': 'Low',
    'ml_detections': 0,
    'rule_detections': 0,
    'heuristic_detections': 0
}

attack_distribution = {
    'Benign': 0,
    'DoS': 0,
    'PortScan': 0,
    'BruteForce': 0,
    'Bot': 0,
    'Infiltration': 0,
    'WebAttack': 0
}

recent_alerts = []
blocked_ips_list = []


def init_idps():
    """Initialize Hybrid IDPS system"""
    global idps, generator
    
    print("Initializing Hybrid IDPS...")
    print("  - ML Detection: Loading...")
    print("  - Rule-Based Detection: Ready")
    print("  ✓ Advanced Pattern Analysis: ENABLED")
    print("  - Manual Blocking: ENABLED")
    
    idps = HybridIDPS(enable_advanced_analysis=True)
    idps.load_models()
    
    # Initialize packet generator
    try:
        import os
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        if idps.selected_features:
            generator = PacketGenerator(idps.selected_features)
        else:
            import joblib
            features_path = os.path.join(base_dir, 'models', 'selected_features.pkl')
            selected_features = joblib.load(features_path)
            generator = PacketGenerator(selected_features)
    except Exception as e:
        print(f"  ⚠ Warning: Could not load specific features, using defaults: {e}")
        # PacketGenerator now supports standalone mode with default features
        generator = PacketGenerator()
    
    print("✓ Hybrid IDPS initialized successfully")
    return True


def monitoring_loop():
    """Background thread for continuous monitoring"""
    global monitoring_active, stats, attack_distribution, recent_alerts
    
    print("Starting enhanced monitoring loop...")
    
    # Generate packet stream with higher attack rate for demo
    packet_stream = generator.generate_traffic_stream(
        duration_seconds=3600,
        packets_per_second=2,
        attack_probability=0.5  # 50% for better demonstration
    )
    
    packet_count = 0
    for packet in packet_stream:
        if not monitoring_active:
            break
        
        packet_count += 1
        
        # Analyze with hybrid detection
        result = idps.predict(packet)
        
        # Update statistics from IDPS
        stats['total_packets'] = idps.stats['total_packets']
        stats['benign'] = idps.stats['benign']
        stats['attacks'] = idps.stats['attacks']
        stats['ml_detections'] = idps.stats['ml_detections']
        stats['rule_detections'] = idps.stats['rule_detections']
        stats['ml_detections'] = idps.stats['ml_detections']
        
        attack_type = result['attack_type']
        
        if result['is_attack']:
            attack_distribution[attack_type] = attack_distribution.get(attack_type, 0) + 1
            
            # Create enhanced alert
            alert = {
                'id': int(time.time() * 1000),
                'type': attack_type,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'confidence': result['confidence'],
                'severity': result['severity'],
                'srcIP': result['src_ip'],
                'blocked': result.get('blocked', False),
                'canBlock': result.get('canBlock', False),
                'detectionMethod': result.get('detection_method', 'unknown'),
                'ruleName': result.get('rule_name', None),
                'ruleDescription': result.get('rule_description', None)
            }
            
            # Add to recent alerts
            recent_alerts.insert(0, alert)
            recent_alerts = recent_alerts[:20]
            
            # Emit alert
            socketio.emit('new_alert', alert)
            
            # Log detection
            method = alert['detectionMethod']
            print(f"[{packet_count}] 🚨 {attack_type} from {result['src_ip']} (via {method})")
        else:
            attack_distribution['Benign'] = attack_distribution.get('Benign', 0) + 1
        
        # Calculate threat level
        if stats['total_packets'] > 0:
            attack_rate = stats['attacks'] / stats['total_packets']
            if attack_rate > 0.35:
                stats['threat_level'] = 'High'
            elif attack_rate > 0.2:
                stats['threat_level'] = 'Medium'
            else:
                stats['threat_level'] = 'Low'
        
        # Update blocked IPs count
        stats['blocked_ips'] = len(idps.blocked_ips)
        
        # Emit updated stats
        socketio.emit('stats_update', {
            'stats': stats,
            'distribution': attack_distribution
        })

        # Store packet for forensics (after result = idps.predict(packet))
        forensic_entry = {
            'packet_id': stats['total_packets'],
            'timestamp': packet['timestamp'],
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'src_port': packet['src_port'],
            'dst_port': packet['dst_port'],
            'protocol': packet['protocol'],
            'label': packet['label'],
            'predicted_type': result['attack_type'],
            'confidence': result['confidence'],
            'severity': result['severity'],
            'detection_method': result.get('detection_method', 'unknown'),
            'is_attack': result['is_attack'],
            'features': packet['features'],  # Full feature vector
            'raw_data': packet  # Complete packet data
        }

        forensic_packets.insert(0, forensic_entry)
        if len(forensic_packets) > MAX_FORENSIC_PACKETS:
            forensic_packets.pop()
        
        time.sleep(0.5)
    
    print("Monitoring loop ended")


@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Get current system status"""
    return jsonify({
        'stats': stats,
        'distribution': attack_distribution,
        'blocked_ips': blocked_ips_list,
        'alerts': [] 
    })


@app.route('/api/inject', methods=['POST'])
def inject_packet():
    """Endpoint for external attacker to inject packets"""
    global stats, attack_distribution, recent_alerts, monitoring_active
    
    if not idps:
        return jsonify({'success': False, 'message': 'IDPS not initialized'}), 500
        
    packet = request.json
    if not packet:
        return jsonify({'success': False, 'message': 'No packet data provided'}), 400
        
    # Process packet through IDPS
    result = idps.predict(packet)
    
    # Update stats
    stats['total_packets'] = idps.stats['total_packets']
    stats['benign'] = idps.stats['benign']
    stats['attacks'] = idps.stats['attacks']
    stats['ml_detections'] = idps.stats['ml_detections']
    stats['rule_detections'] = idps.stats['rule_detections']
    
    attack_type = result['attack_type']
    
    # Store packet for forensics
    forensic_entry = {
        'packet_id': stats['total_packets'],
        'timestamp': packet.get('timestamp', datetime.now().strftime('%H:%M:%S')),
        'src_ip': packet.get('src_ip', 'unknown'),
        'dst_ip': packet.get('dst_ip', 'unknown'),
        'src_port': packet.get('src_port', 0),
        'dst_port': packet.get('dst_port', 0),
        'protocol': packet.get('protocol', 'TCP'),
        'label': packet.get('label', 'unknown'),
        'predicted_type': result['attack_type'],
        'confidence': result['confidence'],
        'severity': result['severity'],
        'detection_method': 'external',
        'is_attack': result['is_attack'],
        'features': packet.get('features', {}),
        'raw_data': packet
    }

    forensic_packets.insert(0, forensic_entry)
    if len(forensic_packets) > MAX_FORENSIC_PACKETS:
        forensic_packets.pop()
    
    if result['is_attack']:
        attack_distribution[attack_type] = attack_distribution.get(attack_type, 0) + 1
        
        # Create alert with External flag
        alert = {
            'id': int(time.time() * 1000),
            'type': attack_type,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'confidence': result['confidence'],
            'severity': result['severity'],
            'srcIP': result['src_ip'],
            'blocked': result.get('blocked', False),
            'canBlock': result.get('canBlock', False),
            'detectionMethod': 'external', # Mark as external attack
            'ruleName': result.get('rule_name', None),
            'ruleDescription': result.get('rule_description', None),
            'is_external': True
        }
        
        # Add to recent alerts
        recent_alerts.insert(0, alert)
        recent_alerts = recent_alerts[:20]
        
        # Emit alert
        socketio.emit('new_alert', alert)
        
        print(f"📡 [EXTERNAL] 🚨 {attack_type} from {result['src_ip']}")
    else:
        attack_distribution['Benign'] = attack_distribution.get('Benign', 0) + 1
        
    # Calculate threat level
    if stats['total_packets'] > 0:
        attack_rate = stats['attacks'] / stats['total_packets']
        if attack_rate > 0.35:
            stats['threat_level'] = 'High'
        elif attack_rate > 0.2:
            stats['threat_level'] = 'Medium'
        else:
            stats['threat_level'] = 'Low'
            
    # Update blocked IPs count
    stats['blocked_ips'] = len(idps.blocked_ips)
    
    # Emit updated stats
    socketio.emit('stats_update', {
        'stats': stats,
        'distribution': attack_distribution
    })
    
    return jsonify({
        'success': True, 
        'result': {
            'is_attack': result['is_attack'],
            'attack_type': result['attack_type'],
            'blocked': result.get('blocked', False)
        }
    })


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start monitoring"""
    global monitoring_active, monitoring_thread
    
    if monitoring_active:
        return jsonify({'success': False, 'message': 'Already monitoring'})
    
    monitoring_active = True
    monitoring_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitoring_thread.start()
    
    return jsonify({'success': True, 'message': 'Monitoring started'})


@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop monitoring"""
    global monitoring_active
    
    monitoring_active = False
    return jsonify({'success': True, 'message': 'Monitoring stopped'})


@app.route('/api/reset', methods=['POST'])
def reset_stats():
    """Reset all statistics"""
    global stats, attack_distribution, recent_alerts
    
    stats = {
        'total_packets': 0,
        'benign': 0,
        'attacks': 0,
        'blocked_ips': 0,
        'threat_level': 'Low',
        'ml_detections': 0,
        'rule_detections': 0,
        'heuristic_detections': 0
    }
    
    attack_distribution = {
        'Benign': 0,
        'DoS': 0,
        'PortScan': 0,
        'BruteForce': 0,
        'Bot': 0,
        'Infiltration': 0,
        'WebAttack': 0
    }
    
    recent_alerts = []
    
    # Reset IDPS stats
    if idps:
        idps.stats = {
            'total_packets': 0,
            'benign': 0,
            'attacks': 0,
            'ml_detections': 0,
            'rule_detections': 0,
            'simulated_detections': 0
        }
    
    return jsonify({'success': True, 'message': 'Statistics reset'})


# ==================== RULE MANAGEMENT ====================

@app.route('/api/rules', methods=['GET'])
def get_rules():
    """Get all blocking rules"""
    if idps:
        rules = idps.rule_engine.get_all_rules()
        
        # Add stats to each rule
        for rule in rules:
            stats = idps.rule_engine.get_rule_stats(rule['id'])
            rule['total_matches'] = stats['total_matches']
            rule['unique_ips'] = stats['unique_ips']
        
        return jsonify(rules)
    return jsonify([])


@app.route('/api/rules', methods=['POST'])
def add_rule():
    """Add a new blocking rule"""
    if not idps:
        return jsonify({'success': False, 'message': 'IDPS not initialized'}), 500
    
    data = request.json
    rule_name = data.get('rule_name')
    rule_type = data.get('rule_type')
    rule_value = data.get('rule_value')
    description = data.get('description', '')
    
    if not all([rule_name, rule_type, rule_value]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        rule_id = idps.rule_engine.add_rule(
            rule_name=rule_name,
            rule_type=rule_type,
            rule_value=rule_value,
            description=description,
            created_by='user'
        )
        
        return jsonify({
            'success': True,
            'message': f'Rule "{rule_name}" added successfully',
            'rule_id': rule_id
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete a blocking rule"""
    if not idps:
        return jsonify({'success': False, 'message': 'IDPS not initialized'}), 500
    
    try:
        idps.rule_engine.remove_rule(rule_id)
        return jsonify({'success': True, 'message': f'Rule {rule_id} deleted'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/rules/<int:rule_id>/toggle', methods=['POST'])
def toggle_rule(rule_id):
    """Enable/disable a rule"""
    if not idps:
        return jsonify({'success': False, 'message': 'IDPS not initialized'}), 500
    
    data = request.json
    enable = data.get('enable', True)
    
    try:
        if enable:
            idps.rule_engine.enable_rule(rule_id)
        else:
            idps.rule_engine.disable_rule(rule_id)
        
        status = 'enabled' if enable else 'disabled'
        return jsonify({'success': True, 'message': f'Rule {rule_id} {status}'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== IP BLOCKING ====================

@app.route('/api/block/<ip>', methods=['POST'])
def block_ip(ip):
    data = request.json
    attack_type = data.get('attack_type', 'Manual')
    
    # 1. Update IDPS internal set
    idps.block_ip(ip) 
    
    # 2. Add to the list used by the UI
    new_block = {
        'address': ip,
        'attackType': attack_type,
        'blockedAt': datetime.now().strftime('%H:%M:%S')
    }
    
    # Avoid duplicates
    if not any(b['address'] == ip for b in blocked_ips_list):
        blocked_ips_list.append(new_block)
        stats['blocked_ips'] = len(blocked_ips_list)
    
    return jsonify({'success': True})

@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP"""
    global blocked_ips_list, stats
    
    if idps:
        success = idps.unblock_ip(ip)
        if success:
            blocked_ips_list = [b for b in blocked_ips_list if b['address'] != ip]
            stats['blocked_ips'] = len(blocked_ips_list)
            
            socketio.emit('ip_unblocked', {'ip': ip})
            
            return jsonify({'success': True, 'message': f'IP {ip} unblocked'})
    
    return jsonify({'success': False, 'message': 'Failed to unblock IP'})

# ==================== FORENSICS ====================

@app.route('/api/forensics/packets', methods=['GET'])
def get_forensic_packets():
    """Get recent packets with full details for forensics"""
    global forensic_packets
    
    filter_type = request.args.get('filter', 'all')
    limit = int(request.args.get('limit', 50))
    
    # Filter packets based on type
    filtered_packets = forensic_packets
    
    if filter_type == 'attacks':
        filtered_packets = [p for p in forensic_packets if p['is_attack']]
    elif filter_type == 'benign':
        filtered_packets = [p for p in forensic_packets if not p['is_attack']]
    
    # Limit results
    result_packets = filtered_packets[:limit]
    
    # Return simplified version (without full raw_data for list view)
    simplified = []
    for packet in result_packets:
        simplified.append({
            'packet_id': packet['packet_id'],
            'timestamp': packet['timestamp'],
            'src_ip': packet['src_ip'],
            'dst_ip': packet['dst_ip'],
            'src_port': packet['src_port'],
            'dst_port': packet['dst_port'],
            'protocol': packet['protocol'],
            'label': packet['label'],
            'predicted_type': packet['predicted_type'],
            'confidence': packet['confidence'],
            'severity': packet['severity'],
            'detection_method': packet['detection_method'],
            'is_attack': packet['is_attack']
        })
    
    return jsonify(simplified)


@app.route('/api/forensics/packet/<int:packet_id>', methods=['GET'])
def get_packet_details(packet_id):
    """Get detailed dissection of a specific packet"""
    global forensic_packets
    
    # Find packet by ID
    packet = None
    for p in forensic_packets:
        if p['packet_id'] == packet_id:
            packet = p
            break
    
    if not packet:
        return jsonify({'error': 'Packet not found'}), 404
    
    # Return full packet details
    return jsonify({
        'packet_id': packet['packet_id'],
        'timestamp': packet['timestamp'],
        'src_ip': packet['src_ip'],
        'dst_ip': packet['dst_ip'],
        'src_port': packet['src_port'],
        'dst_port': packet['dst_port'],
        'protocol': packet['protocol'],
        'label': packet['label'],
        'predicted_type': packet['predicted_type'],
        'confidence': packet['confidence'],
        'severity': packet['severity'],
        'detection_method': packet['detection_method'],
        'is_attack': packet['is_attack'],
        'features': packet['features']
    })


@app.route('/api/forensics/export', methods=['POST'])
def export_forensic_data():
    """Export forensic data (CSV/JSON)"""
    global forensic_packets
    
    data = request.json
    format_type = data.get('format', 'csv')
    filter_type = data.get('filter', 'all')
    
    # Filter packets
    filtered_packets = forensic_packets
    
    if filter_type == 'attacks':
        filtered_packets = [p for p in forensic_packets if p['is_attack']]
    elif filter_type == 'benign':
        filtered_packets = [p for p in forensic_packets if not p['is_attack']]
    
    if format_type == 'csv':
        import csv
        from io import StringIO
        
        output = StringIO()
        
        if not filtered_packets:
            return jsonify({'error': 'No data to export'}), 400
        
        # Get all feature names from first packet
        feature_names = list(filtered_packets[0]['features'].keys()) if filtered_packets[0]['features'] else []
        
        # CSV headers
        fieldnames = [
            'packet_id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'true_label', 'predicted_type', 'confidence', 'severity',
            'detection_method', 'is_attack'
        ] + feature_names
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for packet in filtered_packets:
            row = {
                'packet_id': packet['packet_id'],
                'timestamp': packet['timestamp'],
                'src_ip': packet['src_ip'],
                'dst_ip': packet['dst_ip'],
                'src_port': packet['src_port'],
                'dst_port': packet['dst_port'],
                'protocol': packet['protocol'],
                'true_label': packet['label'],
                'predicted_type': packet['predicted_type'],
                'confidence': packet['confidence'],
                'severity': packet['severity'],
                'detection_method': packet['detection_method'],
                'is_attack': packet['is_attack']
            }
            # Add features
            for feat_name in feature_names:
                row[feat_name] = packet['features'].get(feat_name, 0)
            
            writer.writerow(row)
        
        output.seek(0)
        
        from flask import Response
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=forensic_data_{int(time.time())}.csv'}
        )
    
    elif format_type == 'json':
        import json
        from flask import Response
        
        # Prepare data for JSON export
        export_data = []
        for packet in filtered_packets:
            export_data.append({
                'packet_id': packet['packet_id'],
                'timestamp': packet['timestamp'],
                'network': {
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'protocol': packet['protocol']
                },
                'transport': {
                    'src_port': packet['src_port'],
                    'dst_port': packet['dst_port']
                },
                'detection': {
                    'true_label': packet['label'],
                    'predicted_type': packet['predicted_type'],
                    'confidence': packet['confidence'],
                    'severity': packet['severity'],
                    'method': packet['detection_method'],
                    'is_attack': packet['is_attack']
                },
                'features': packet['features']
            })
        
        json_data = json.dumps(export_data, indent=2)
        
        return Response(
            json_data,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=forensic_data_{int(time.time())}.json'}
        )
    
    return jsonify({'error': 'Invalid format'}), 400


@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print('Client connected')
    emit('status', {'monitoring': monitoring_active})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    print('Client disconnected')


if __name__ == '__main__':
    print("="*70)
    print("Enhanced CICIDS2017 IDPS Web Server")
    print("="*70)
    print("Features:")
    print("  ✓ ML Detection (trained models)")
    print("  ✓ Rule-Based Detection (custom user rules)")
    print("  ✓ UI Attack Diversity (shows variety even if ML limited)")
    print("  ✓ Manual IP Blocking")
    print("  ✓ Real-time WebSocket Updates")
    print("="*70)
    
    # Initialize IDPS
    if not init_idps():
        print("\n⚠️  Warning: IDPS initialization failed")
    
    print("\n🚀 Starting Flask server...")
    print("Dashboard URL: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("="*70 + "\n")
    
    # Run server
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
