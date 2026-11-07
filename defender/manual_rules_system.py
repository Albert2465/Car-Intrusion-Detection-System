"""
Manual Rule-Based Blocking System
User can create custom rules to block traffic
"""

import sqlite3
from datetime import datetime
import re

class RuleEngine:
    """
    Rule engine for custom blocking rules
    Users can create rules like:
    - Block IP address
    - Block IP range
    - Block specific ports
    - Block protocol types
    """
    
    def __init__(self, db_path=None):
        import os
        if db_path is None:
            # Use absolute path relative to this script
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(base_dir, 'idps_rules.db')
        else:
            self.db_path = db_path
            
        self.rules = []
        self._init_database()
        self._load_rules()
        print(f"✓ Rule Engine initialized (DB: {self.db_path})")
    
    def _init_database(self):
        """Initialize rules database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocking_rules (
                rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                rule_value TEXT NOT NULL,
                action TEXT DEFAULT 'block',
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP,
                created_by TEXT DEFAULT 'user',
                description TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER,
                timestamp TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                FOREIGN KEY (rule_id) REFERENCES blocking_rules(rule_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_rules(self):
        """Load active rules from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rule_id, rule_name, rule_type, rule_value, action, description
            FROM blocking_rules
            WHERE enabled = 1
        ''')
        
        self.rules = []
        for row in cursor.fetchall():
            self.rules.append({
                'id': row[0],
                'name': row[1],
                'type': row[2],
                'value': row[3],
                'action': row[4],
                'description': row[5]
            })
        
        conn.close()
        print(f"  Loaded {len(self.rules)} active rules")
    
    def add_rule(self, rule_name, rule_type, rule_value, description="", created_by="user"):
        """
        Add a new blocking rule
        
        Rule types:
        - ip_exact: Exact IP match (e.g., "192.168.1.100")
        - ip_range: IP range (e.g., "192.168.1.0/24")
        - port: Specific port (e.g., "22")
        - port_range: Port range (e.g., "1-1024")
        - protocol: Protocol type (e.g., "SSH", "FTP")
        - country: Block by country code (e.g., "CN", "RU")
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO blocking_rules 
            (rule_name, rule_type, rule_value, created_at, created_by, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (rule_name, rule_type, rule_value, datetime.now(), created_by, description))
        
        rule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Reload rules
        self._load_rules()
        
        print(f"✓ Rule added: {rule_name} ({rule_type}: {rule_value})")
        return rule_id
    
    def remove_rule(self, rule_id):
        """Remove a rule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM blocking_rules WHERE rule_id = ?', (rule_id,))
        conn.commit()
        conn.close()
        
        self._load_rules()
        print(f"✓ Rule {rule_id} removed")
    
    def disable_rule(self, rule_id):
        """Disable a rule without deleting it"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE blocking_rules SET enabled = 0 WHERE rule_id = ?', (rule_id,))
        conn.commit()
        conn.close()
        
        self._load_rules()
    
    def enable_rule(self, rule_id):
        """Enable a disabled rule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE blocking_rules SET enabled = 1 WHERE rule_id = ?', (rule_id,))
        conn.commit()
        conn.close()
        
        self._load_rules()
    
    def check_packet(self, packet):
        """
        Check if packet matches any blocking rule
        Returns: (should_block, matching_rule)
        """
        src_ip = packet.get('src_ip', '')
        dst_port = packet.get('dst_port', 0)
        protocol = packet.get('protocol', '').upper()
        
        for rule in self.rules:
            rule_type = rule['type']
            rule_value = rule['value']
            
            # Check IP exact match
            if rule_type == 'ip_exact' and src_ip == rule_value:
                self._log_match(rule['id'], packet)
                return (True, rule)
            
            # Check IP range (simple CIDR check)
            if rule_type == 'ip_range' and self._ip_in_range(src_ip, rule_value):
                self._log_match(rule['id'], packet)
                return (True, rule)
            
            # Check port exact match
            if rule_type == 'port' and str(dst_port) == rule_value:
                self._log_match(rule['id'], packet)
                return (True, rule)
            
            # Check port range
            if rule_type == 'port_range' and self._port_in_range(dst_port, rule_value):
                self._log_match(rule['id'], packet)
                return (True, rule)
            
            # Check protocol
            if rule_type == 'protocol' and protocol == rule_value.upper():
                self._log_match(rule['id'], packet)
                return (True, rule)
        
        return (False, None)
    
    def _ip_in_range(self, ip, cidr):
        """Check if IP is in CIDR range (simplified)"""
        try:
            if '/' in cidr:
                network, bits = cidr.split('/')
                network_parts = [int(x) for x in network.split('.')]
                ip_parts = [int(x) for x in ip.split('.')]
                bits = int(bits)
                
                # Simple subnet mask check for first octets
                octets_to_check = bits // 8
                for i in range(octets_to_check):
                    if network_parts[i] != ip_parts[i]:
                        return False
                return True
            return False
        except:
            return False
    
    def _port_in_range(self, port, port_range):
        """Check if port is in range"""
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return start <= port <= end
            return False
        except:
            return False
    
    def _log_match(self, rule_id, packet):
        """Log when a rule matches"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO rule_matches (rule_id, timestamp, src_ip, dst_ip, dst_port, protocol)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (rule_id, datetime.now(), packet.get('src_ip'), packet.get('dst_ip'),
              packet.get('dst_port'), packet.get('protocol')))
        
        conn.commit()
        conn.close()
    
    def get_all_rules(self):
        """Get all rules (enabled and disabled)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rule_id, rule_name, rule_type, rule_value, action, enabled, 
                   created_at, created_by, description
            FROM blocking_rules
            ORDER BY created_at DESC
        ''')
        
        rules = []
        for row in cursor.fetchall():
            rules.append({
                'id': row[0],
                'name': row[1],
                'type': row[2],
                'value': row[3],
                'action': row[4],
                'enabled': bool(row[5]),
                'created_at': row[6],
                'created_by': row[7],
                'description': row[8]
            })
        
        conn.close()
        return rules
    
    def get_rule_stats(self, rule_id):
        """Get statistics for a specific rule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM rule_matches WHERE rule_id = ?
        ''', (rule_id,))
        
        total_matches = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(DISTINCT src_ip) FROM rule_matches WHERE rule_id = ?
        ''', (rule_id,))
        
        unique_ips = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_matches': total_matches,
            'unique_ips': unique_ips
        }


# Example usage
if __name__ == "__main__":
    print("="*60)
    print("Manual Rule Engine - Example Usage")
    print("="*60)
    
    engine = RuleEngine()
    
    # Add some example rules
    print("\nAdding example rules...")
    
    engine.add_rule(
        rule_name="Block Suspicious IP",
        rule_type="ip_exact",
        rule_value="185.220.101.50",
        description="Known malicious IP from threat intel"
    )
    
    engine.add_rule(
        rule_name="Block China IP Range",
        rule_type="ip_range",
        rule_value="117.0.0.0/8",
        description="Block traffic from China"
    )
    
    engine.add_rule(
        rule_name="Block Telnet",
        rule_type="port",
        rule_value="23",
        description="Telnet is insecure, block all attempts"
    )
    
    engine.add_rule(
        rule_name="Block Privileged Ports",
        rule_type="port_range",
        rule_value="1-1024",
        description="Block access to privileged ports"
    )
    
    # Test packet matching
    print("\nTesting packet matching...")
    
    test_packets = [
        {'src_ip': '185.220.101.50', 'dst_port': 80, 'protocol': 'TCP'},
        {'src_ip': '117.25.30.45', 'dst_port': 443, 'protocol': 'TCP'},
        {'src_ip': '192.168.1.100', 'dst_port': 23, 'protocol': 'TCP'},
        {'src_ip': '192.168.1.100', 'dst_port': 8080, 'protocol': 'TCP'}
    ]
    
    for packet in test_packets:
        should_block, rule = engine.check_packet(packet)
        if should_block:
            print(f"  ❌ BLOCKED: {packet['src_ip']}:{packet['dst_port']} - Rule: {rule['name']}")
        else:
            print(f"  ✓ ALLOWED: {packet['src_ip']}:{packet['dst_port']}")
    
    # Show all rules
    print("\n📋 All Rules:")
    for rule in engine.get_all_rules():
        status = "✓ Enabled" if rule['enabled'] else "✗ Disabled"
        print(f"  [{rule['id']}] {rule['name']} ({rule['type']}: {rule['value']}) - {status}")
        
        # Get stats
        stats = engine.get_rule_stats(rule['id'])
        print(f"      Matches: {stats['total_matches']}, Unique IPs: {stats['unique_ips']}")
    
    print("\n✓ Rule engine demonstration complete!")