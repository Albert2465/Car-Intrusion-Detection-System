"""
Network Packet Generator for CICIDS2017 IDPS Testing
Uses REAL packets from dataset + synthetic generation
Excludes DoS/DDoS attacks - only other attack types
"""

import numpy as np
import pandas as pd
import time
import random
from datetime import datetime
import json

class PacketGenerator:
    """
    Generates network packets using real CICIDS2017 data
    Combines dataset packets with synthetic generation
    Excludes DoS/DDoS varieties
    """
    
    def __init__(self, selected_features, dataset_path=None):
        self.selected_features = selected_features
        self.num_features = len(selected_features)
        
        # Load dataset if provided
        self.dataset = None
        self.dataset_packets = {
            'Benign': [],
            'PortScan': [],
            'BruteForce': [],
            'Bot': [],
            'Infiltration': [],
            'WebAttack': []
        }
        
        if dataset_path:
            self._load_dataset(dataset_path)
        
        # REALISTIC PUBLIC IP POOLS for external sources
        self.benign_public_ips = [
            f"203.0.113.{i}" for i in range(10, 50)
        ]
        
        # ATTACKER IP POOLS
        self.attacker_public_ips = [
            f"185.111.121.{random.randint(1, 22)}" 
            for _ in range(20)
        ]
        
        # PRIVATE IP POOLS for internal servers
        self.server_private_ips = [
            f"192.168.1.{i}" for i in range(10, 20)
        ] 
        
        self.blocked_ips = set()
        
        print(f"✓ Packet Generator initialized")
        print(f"  - {len(self.benign_public_ips)} benign public IPs")
        print(f"  - {len(self.attacker_public_ips)} attacker public IPs")
        print(f"  - {len(self.server_private_ips)} internal server IPs")
        if self.dataset is not None:
            print(f"  - Dataset loaded with {len(self.dataset)} packets")
            for label, packets in self.dataset_packets.items():
                if packets:
                    print(f"    • {label}: {len(packets)} packets")
    
    def _load_dataset(self, dataset_path):
        """Load and filter dataset - exclude DoS/DDoS attacks"""
        print(f"Loading dataset from {dataset_path}...")
        
        try:
            # Load dataset
            df = pd.read_csv(dataset_path)
            
            # Map dataset labels to our categories (excluding DoS/DDoS)
            label_mapping = {
                'BENIGN': 'Benign',
                'PortScan': 'PortScan',
                'FTP-Patator': 'BruteForce',
                'SSH-Patator': 'BruteForce',
                'Bot': 'Bot',
                'Infiltration': 'Infiltration',
                'Web Attack – Brute Force': 'WebAttack',
                'Web Attack – XSS': 'WebAttack',
                'Web Attack – Sql Injection': 'WebAttack',
            }
            
            # Filter out DoS/DDoS attacks
            dos_keywords = ['DoS', 'DDoS', 'Slowloris', 'Hulk', 'GoldenEye', 'Heartbleed']
            
            # Get label column (might be named differently)
            label_col = None
            for col in df.columns:
                if 'label' in col.lower() or col.strip() == 'Label':
                    label_col = col
                    break
            
            if label_col is None:
                print("⚠ Warning: Could not find label column, using last column")
                label_col = df.columns[-1]
            
            # Filter and organize packets
            for idx, row in df.iterrows():
                original_label = str(row[label_col]).strip()
                
                # Skip DoS/DDoS attacks
                if any(keyword in original_label for keyword in dos_keywords):
                    continue
                
                # Map to our categories
                mapped_label = label_mapping.get(original_label)
                if mapped_label:
                    # Extract features
                    packet_features = {}
                    for feat in self.selected_features:
                        if feat in row:
                            packet_features[feat] = float(row[feat]) if pd.notna(row[feat]) else 0.0
                    
                    if packet_features:  # Only add if we have features
                        self.dataset_packets[mapped_label].append(packet_features)
            
            self.dataset = df
            print(f"✓ Dataset loaded successfully")
            
        except Exception as e:
            print(f"⚠ Warning: Could not load dataset: {e}")
            print("  Will use synthetic generation only")
    
    def _create_packet_from_features(self, features_dict, label, dataset_probability=0.7):
        """
        Enforces the split: 
        - 70% chance to pull real features from self.dataset_packets
        - 30% chance to use synthetic features_dict
        """
        # Randomly decide source based on your 70% requirement
        use_dataset = random.random() < dataset_probability
        
        if use_dataset and label in self.dataset_packets and self.dataset_packets[label]:
            # Use real features from dataset
            features = random.choice(self.dataset_packets[label])
            source_label = 'dataset'
        else:
            # Use provided synthetic features
            features = features_dict
            source_label = 'synthetic'
        
        # Determine IPs based on label
        if label == 'Benign':
            src_ip = random.choice(self.benign_public_ips)
            dst_port = random.choice([80, 443, 22, 3306, 8080])
        else:
            src_ip = random.choice(self.attacker_public_ips)
            if label == 'PortScan':
                dst_port = random.randint(1, 65535)
            elif label == 'BruteForce':
                dst_port = random.choice([22, 21, 3389])
            elif label == 'WebAttack':
                dst_port = random.choice([80, 443, 8080])
            else:
                dst_port = random.randint(1024, 65535)
        
        packet = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': random.choice(self.server_private_ips),
            'src_port': random.randint(1024, 65535),
            'dst_port': dst_port,
            'protocol': 'TCP',
            'label': label,
            'features': features,
            'source': source_label
        }
        
        return packet

    # Update ALL these methods to accept dataset_probability
    def generate_benign_packet(self, dataset_probability=0.7):
        features = {feat: float(val) for feat, val in 
                   zip(self.selected_features, np.random.beta(2, 5, self.num_features))}
        return self._create_packet_from_features(features, 'Benign', dataset_probability)

    def generate_portscan_packet(self, dataset_probability=0.7):
        features_vals = np.random.uniform(0.3, 0.7, self.num_features)
        features_vals[5:10] = np.random.uniform(0.7, 0.95, min(5, self.num_features-5))
        features = {feat: float(val) for feat, val in zip(self.selected_features, features_vals)}
        return self._create_packet_from_features(features, 'PortScan', dataset_probability)

    def generate_bruteforce_packet(self, dataset_probability=0.7):
        features_vals = np.random.uniform(0.4, 0.8, self.num_features)
        if self.num_features > 15:
            features_vals[10:15] = np.random.uniform(0.75, 0.9, 5)
        features = {feat: float(val) for feat, val in zip(self.selected_features, features_vals)}
        return self._create_packet_from_features(features, 'BruteForce', dataset_probability)

    def generate_bot_packet(self, dataset_probability=0.7):
        features_vals = np.random.uniform(0.35, 0.75, self.num_features)
        if self.num_features > 20:
            features_vals[15:20] = np.random.uniform(0.65, 0.85, 5)
        features = {feat: float(val) for feat, val in zip(self.selected_features, features_vals)}
        return self._create_packet_from_features(features, 'Bot', dataset_probability)

    def generate_infiltration_packet(self, dataset_probability=0.7):
        features_vals = np.random.uniform(0.45, 0.85, self.num_features)
        if self.num_features > 25:
            features_vals[20:25] = np.random.uniform(0.8, 0.95, 5)
        features = {feat: float(val) for feat, val in zip(self.selected_features, features_vals)}
        return self._create_packet_from_features(features, 'Infiltration', dataset_probability)

    def generate_webattack_packet(self, dataset_probability=0.7):
        features_vals = np.random.uniform(0.4, 0.75, self.num_features)
        if self.num_features > 30:
            features_vals[25:30] = np.random.uniform(0.7, 0.9, 5)
        features = {feat: float(val) for feat, val in zip(self.selected_features, features_vals)}
        return self._create_packet_from_features(features, 'WebAttack', dataset_probability)

    def generate_random_packet(self, attack_probability=0.6):
        """
        Traffic Mix: 
        - 60% Attack (attack_probability=0.6)
        - 40% Benign 
        """
        # 1. 60/40 Traffic Mix Check
        if random.random() > attack_probability:
            # 40% Chance: Benign
            return self.generate_benign_packet(dataset_probability=0.7)
        
        # 2. 60% Chance: It is an Attack. Pick a category.
        attack_types = ['PortScan', 'BruteForce', 'Bot', 'Infiltration', 'WebAttack']
        selected_attack = random.choice(attack_types)
        
        # 3. Use the 70% Dataset rule for the attack
        return self.generate_specific_attack(selected_attack, dataset_probability=0.7)
    
    def generate_specific_attack(self, attack_type, dataset_probability=0.7):
        """Helper to route attacks while applying the dataset probability rule"""
        mapping = {
            'PortScan': self.generate_portscan_packet,
            'BruteForce': self.generate_bruteforce_packet,
            'Bot': self.generate_bot_packet,
            'Infiltration': self.generate_infiltration_packet,
            'WebAttack': self.generate_webattack_packet
        }
        # Pass the dataset_probability down to the generator
        return mapping[attack_type](dataset_probability=dataset_probability)

    def generate_traffic_stream(self, duration_seconds=60, packets_per_second=10, attack_probability=0.3):
        """Generate continuous traffic stream"""
        end_time = time.time() + duration_seconds
        packet_interval = 1.0 / packets_per_second
        packet_count = 0
        
        while time.time() < end_time:
            packet = self.generate_random_packet(attack_probability)
            packet['packet_id'] = packet_count
            packet_count += 1
            yield packet
            time.sleep(packet_interval)
    
    def generate_attack_scenario(self, attack_type, num_packets=100):
        """Generate specific attack scenario (NO DoS/DDoS)"""
        generators = {
            'PortScan': self.generate_portscan_packet,
            'BruteForce': self.generate_bruteforce_packet,
            'Bot': self.generate_bot_packet,
            'Infiltration': self.generate_infiltration_packet,
            'WebAttack': self.generate_webattack_packet
        }
        
        if attack_type in ['DoS', 'DDoS']:
            raise ValueError(f"DoS/DDoS attacks are excluded from this generator")
        
        generator = generators.get(attack_type)
        if not generator:
            raise ValueError(f"Unknown attack type: {attack_type}. Available: {list(generators.keys())}")
        
        packets = []
        for i in range(num_packets):
            packet = generator()
            packet['packet_id'] = i
            packets.append(packet)
        
        return packets
    
    def export_to_csv(self, packets, filename='generated_traffic.csv'):
        """Export generated packets to CSV"""
        records = []
        for packet in packets:
            record = {
                'timestamp': packet['timestamp'],
                'src_ip': packet['src_ip'],
                'dst_ip': packet['dst_ip'],
                'src_port': packet['src_port'],
                'dst_port': packet['dst_port'],
                'protocol': packet['protocol'],
                'label': packet['label'],
                'source': packet.get('source', 'unknown')
            }
            record.update(packet['features'])
            records.append(record)
        
        df = pd.DataFrame(records)
        df.to_csv(filename, index=False)
        print(f"✓ Exported {len(packets)} packets to {filename}")
        
        # Show statistics
        print(f"\n📊 Packet sources:")
        if 'source' in df.columns:
            print(df['source'].value_counts())
        
        return df


# ============= EXAMPLE USAGE =============
if __name__ == "__main__":
    import joblib
    
    # Load features
    try:
        selected_features = joblib.load('models/selected_features.pkl')
    except:
        selected_features = [f'feature_{i}' for i in range(50)]
    
    # Initialize generator WITH dataset
    print("\n" + "="*60)
    print("Enhanced Packet Generator - Real Dataset + Synthetic")
    print("NO DoS/DDoS attacks - Other attacks only")
    print("="*60)
    
    # Option 1: With dataset
    generator = PacketGenerator(
        selected_features, 
        dataset_path='path/to/CICIDS2017.csv'  # Update this path
    )
    
    # Option 2: Without dataset (synthetic only)
    # generator = PacketGenerator(selected_features)
    
    # Generate mixed traffic
    print("\n1. Generating mixed traffic...")
    packets = []
    for packet in generator.generate_traffic_stream(
        duration_seconds=10, 
        packets_per_second=5,
        attack_probability=0.4
    ):
        packets.append(packet)
        source = packet.get('source', 'unknown')
        print(f"  [{source}] {packet['label']} | {packet['src_ip']} → {packet['dst_ip']}")
    
    # Generate specific attacks
    print("\n2. Generating BruteForce scenario...")
    brute_packets = generator.generate_attack_scenario('BruteForce', num_packets=20)
    
    # Export
    print("\n3. Exporting to CSV...")
    all_packets = packets + brute_packets
    df = generator.export_to_csv(all_packets, 'enhanced_traffic.csv')
    
    print(f"\n📊 Attack Distribution:")
    print(df['label'].value_counts())