
# Hybrid Intrusion Detection System (IDPS) + Attack Simulation Platform

## Overview

This project is a cybersecurity simulation platform that demonstrates how an attacker can generate network attacks and how a defender system can detect and block suspicious traffic in real time. It combines:

- an attacker dashboard that launches various attacks
- a defender dashboard that monitors traffic and classifies packets
- machine learning models for network attack detection
- rule-based blocking logic
- live updates using Flask and Socket.IO
- forensic packet tracking for analysis

The system is built as a research/demo application for learning network security, intrusion detection, and threat analysis.

---

## Architecture

The project is divided into two major components:

### 1. Attacker Module
Location: attacker/

This side simulates malicious activity. It creates traffic patterns associated with attack types such as:

- PortScan
- BruteForce
- Bot
- Infiltration
- DoS
- WebAttack

The attacker app:

- provides a web dashboard to launch attacks
- generates attack packets
- sends packets to the defender API
- shows live stats such as sent packets, blocked attempts, and attack rate

Key files:
- attacker/attacker_app.py
- attacker/packet_generator.py
- attacker/templates/attacker.html
- attacker/templates/attack_page.html

### 2. Defender Module
Location: defender/

This side acts as the security system. It receives incoming packets and analyzes them through a hybrid pipeline:

- Machine learning detection
- Heuristic analysis
- Rule-based detection
- Manual blocking of suspicious IPs/ports

The defender app:

- exposes the dashboard
- receives packets through /api/inject
- evaluates packet risk
- updates attack statistics
- blocks malicious traffic according to rules
- stores forensic packet data

Key files:
- defender/app.py
- defender/hybrid_detection_system.py
- defender/manual_rules_system.py
- defender/packet_generator.py
- defender/templates/dashboard.html
- defender/idps_rules.db

### 3. Model Layer
Location: defender/models/

The defender loads trained ML models to classify traffic:

- dt_model.pkl
- rf_model.pkl
- et_model.pkl
- xg_model.pkl
- stk_model.pkl
- label_encoder.pkl
- selected_features.pkl
- feature_min.pkl
- feature_max.pkl
- scaler.pkl

These models help the system identify whether incoming packets are benign or malicious and classify the attack type.

---

## System Workflow

1. The attacker generates a packet or attack stream.
2. The attacker sends this packet to the defender using HTTP POST requests.
3. The defender receives the packet and checks it with the IDPS logic.
4. The packet is classified using:
   - ML prediction
   - heuristic checks
   - custom rules
5. The system updates:
   - alert logs
   - threat level
   - blocked IPs
   - attack distribution
6. The dashboard refreshes in real time via Socket.IO.

---

## Functional Features

### Attack Simulation
The attacker module supports multiple attack styles:
- Port scanning
- Credential brute-force
- Bot traffic
- Infiltration attempts
- Denial of service attempts
- Web exploitation patterns

### Intrusion Detection
The defender uses a hybrid IDPS approach:
- machine learning
- rule matching
- statistical/behavioral heuristic checks

### Manual Blocking
The manual rules engine allows users to create rules such as:
- block IP address
- block IP range
- block specific port
- block port range
- block protocol type

Rules are stored in SQLite.

### Real-time Dashboard
The dashboard displays:
- total packets
- benign traffic
- attack counts
- blocked IP count
- threat level
- attack distribution
- recent alerts

### Forensics
The system stores packet-level details including:
- source and destination IPs
- ports
- protocol
- true label
- predicted label
- confidence
- severity
- detection method
- feature vector

This helps with later investigation and export.

---

## Requirements

### Python Version
Recommended:
- Python 3.9+
- Python 3.10 or 3.11 preferred

### Attacker Dependencies
The attacker app depends on:
- Flask
- Flask-SocketIO
- Requests
- NumPy
- Pandas
- Eventlet

File:
- attacker/requirements.txt

### Defender Dependencies
The defender app depends on:
- Flask
- Flask-CORS
- Flask-SocketIO
- NumPy
- Pandas
- Scikit-learn
- Joblib
- XGBoost
- Matplotlib
- Seaborn
- Imbalanced-learn
- Eventlet

File:
- defender/requirements.txt

---

## Installation

Create a virtual environment:

Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

Install attacker dependencies:
```bash
cd attacker
pip install -r requirements.txt
```

Install defender dependencies:
```bash
cd ../defender
pip install -r requirements.txt
```

---

## How to Run

### 1. Start the Defender
From the project root:
```bash
cd defender
python app.py
```

This starts the IDPS dashboard at:
- http://localhost:5000

### 2. Start the Attacker
Open another terminal and run:
```bash
cd attacker
python attacker_app.py
```

This starts the attacker dashboard at:
- http://localhost:5001

### 3. Use the dashboards
- Open the defender URL to monitor the traffic and alerts
- Open the attacker URL to launch attack scenarios

---

## Detailed Project Description

This project is designed as a practical demonstration of how intrusion detection systems work in a controlled lab environment. It simulates both sides of the security flow:

- attacker side: generates malicious traffic
- defender side: analyzes, detects, and blocks malicious activity

The main idea is to show how a hybrid IDPS can combine multiple techniques to improve detection quality. Instead of relying on just one model or one rule, the system combines:

- ML-based prediction
- rule-based filtering
- heuristic pattern checks
- manual blocking

The project is especially useful for:
- cybersecurity education
- demo preparation
- IDS/IPS research projects
- academic projects
- learning how Flask web apps can be used for security dashboards

### Why this project matters
Modern networks face several attack types, and organizations need systems that can identify suspicious activity early. This project demonstrates a simplified version of that process using real-world-inspired packet features and attack categories.

### Real-world use case
Imagine a corporate network where suspicious traffic appears from unknown sources. The defender receives the packets, classifies them, detects associated attack patterns, and blocks malicious IPs before they can continue their activity. This is the key concept the project demonstrates.

---

## Project Structure

```text
my_project/
├── app.py
├── dashboard.html
├── attacker/
│   ├── attacker_app.py
│   ├── packet_generator.py
│   ├── requirements.txt
│   └── templates/
│       ├── attacker.html
│       └── attack_page.html
├── defender/
│   ├── app.py
│   ├── hybrid_detection_system.py
│   ├── idps_rules.db
│   ├── manual_rules_system.py
│   ├── packet_generator.py
│   ├── requirements.txt
│   ├── selecteed_data.py
│   ├── test.py
│   ├── models/
│   │   ├── dt_model.pkl
│   │   ├── et_model.pkl
│   │   ├── feature_max.pkl
│   │   ├── feature_min.pkl
│   │   ├── label_encoder.pkl
│   │   ├── rf_model.pkl
│   │   ├── scaler.pkl
│   │   ├── selected_features.pkl
│   │   ├── stk_model.pkl
│   │   └── xg_model.pkl
│   └── templates/
│       └── dashboard.html
├── attacker.zip
├── defender.zip
└── README.md
```

---

## Notes

This project is a demonstration platform and not a production-grade enterprise security product. It is designed to:

- simulate intrusion detection scenarios
- teach detection concepts
- prototype ML-based security flows
- show real-time dashboard behavior

---

## Summary

This project demonstrates a complete intrusion detection workflow:

- attack generation
- packet injection
- classification and detection
- rule-based prevention
- monitoring and alerting
- forensic packet analysis

It is a strong example of how a hybrid security system can be built from Python, Flask, machine learning, and real-time web technologies.

If you want, I can also create:
- a shorter project summary version
- a formal academic report version
- a presentation-ready README
- a UML/architecture diagram in text form
