# 📡 Real-Time Network Traffic Analyzer with ML-Based Intrusion Detection

## 📌 Overview

This project is a **real-time network monitoring and intrusion detection system** built using **Python, Scapy, and Streamlit**. It captures live network traffic, analyzes protocols and ports, detects anomalies, and visualizes insights through an interactive dashboard.

---

## 🚀 Features

### 🔍 Network Monitoring

* Live packet capture using Scapy
* Protocol detection (TCP, UDP, ICMP)
* Source & destination IP tracking

### 📊 Analytics Dashboard

* Protocol distribution visualization
* Top active IP addresses
* Real-time packet logs

### ⚠️ Intrusion Detection System (IDS)

* Suspicious port detection (FTP, SSH, Telnet, RDP)
* High-traffic IP anomaly detection
* Rule-based alerts

### 🤖 Machine Learning

* Anomaly detection using **Isolation Forest**
* Identifies unusual traffic patterns

### 🔐 Authentication

* Login system for dashboard access

### 📁 Data Handling

* Export logs as CSV
* Structured packet storage for analysis

### 🐳 Deployment

* Docker support for easy deployment

---

## 🛠️ Tech Stack

* **Programming Language:** Python
* **Networking Library:** Scapy
* **Frontend/UI:** Streamlit
* **Data Processing:** Pandas
* **Visualization:** Matplotlib
* **Machine Learning:** Scikit-learn

---

## 📂 Project Structure

```
Network-Traffic-Analyzer/
│
├── app.py              # Main Streamlit dashboard
├── auth.py             # Authentication module
├── requirements.txt    # Dependencies
├── Dockerfile          # Containerization
├── .gitignore
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository

```
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer
```

### 2. Install dependencies

```
pip install -r requirements.txt
```

---

## ▶️ Running the Application

### Run locally:

```
sudo streamlit run app.py
```

### Access in browser:

```
http://localhost:8501
```

---

## 🔐 Login Credentials

```
Username: admin
Password: admin123
```

---

## 🐳 Docker Setup

### Build image:

```
docker build -t network-analyzer .
```

### Run container:

```
docker run -p 8501:8501 network-analyzer
```

---

## 📊 How It Works

```
Network Traffic
      ↓
Scapy Packet Capture
      ↓
Packet Processing (Protocol + Ports)
      ↓
Detection Engine (Rules + ML)
      ↓
Streamlit Dashboard Visualization
```

---

## ⚠️ Detection Logic

### Rule-Based:

* Flags suspicious ports (21, 22, 23, 3389)
* Detects high-frequency traffic from a single IP

### ML-Based:

* Uses Isolation Forest
* Detects anomalies based on port behavior

---

## 📌 Future Enhancements

* Real-time streaming (WebSockets)
* Database integration (PostgreSQL)
* Cloud deployment (AWS/GCP)
* SIEM integration (ELK stack)
* Alert system (Email/Slack notifications)

---

## 🎯 Use Cases

* Network monitoring
* Cybersecurity analysis
* Intrusion detection systems
* Educational demonstration of network protocols

---

## 🧠 Key Learnings

* Packet sniffing and protocol analysis
* Real-time dashboard development
* Intrusion detection techniques
* Machine learning for anomaly detection
* Full-stack project integration

