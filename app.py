import streamlit as st

# -----------------------------
# MUST BE FIRST STREAMLIT CALL
# -----------------------------
st.set_page_config(page_title="Network Analyzer", layout="wide")

# -----------------------------
# Imports
# -----------------------------
from auth import login, check_auth
from scapy.all import sniff
from collections import Counter
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest

# -----------------------------
# Styling (Dark UI)
# -----------------------------
st.markdown("""
<style>
.stApp {
    background-color: #0E1117;
    color: white;
}
</style>
""", unsafe_allow_html=True)

# -----------------------------
# Authentication
# -----------------------------
login()

if not check_auth():
    st.warning("Please login to access dashboard")
    st.stop()

# -----------------------------
# Title
# -----------------------------
st.title("📡 Real-Time Network Traffic Analyzer")

# -----------------------------
# Session State
# -----------------------------
if "logs" not in st.session_state:
    st.session_state.logs = []

if "protocol_count" not in st.session_state:
    st.session_state.protocol_count = Counter()

if "ip_counter" not in st.session_state:
    st.session_state.ip_counter = Counter()

if "running" not in st.session_state:
    st.session_state.running = False

# -----------------------------
# Sidebar Controls
# -----------------------------
st.sidebar.header("Controls")

packet_limit = st.sidebar.slider("Packets per cycle", 10, 100, 20)
protocol_filter = st.sidebar.selectbox("Filter", ["ip", "tcp", "udp"])

start = st.sidebar.button("▶ Start")
stop = st.sidebar.button("⏹ Stop")
clear = st.sidebar.button("🧹 Clear Data")

if start:
    st.session_state.running = True

if stop:
    st.session_state.running = False

if clear:
    st.session_state.logs = []
    st.session_state.protocol_count = Counter()
    st.session_state.ip_counter = Counter()

# -----------------------------
# Detection Rules
# -----------------------------
suspicious_ports = [21, 22, 23, 3389]
IP_THRESHOLD = 15

# -----------------------------
# Packet Processing
# -----------------------------
def process_packet(packet):
    if packet.haslayer("IP"):
        ip = packet["IP"]
        src, dst = ip.src, ip.dst
        timestamp = datetime.now().strftime('%H:%M:%S')

        st.session_state.ip_counter[src] += 1

        log = {
            "time": timestamp,
            "src": src,
            "dst": dst,
            "protocol": "",
            "sport": 0,
            "dport": 0,
            "alert": ""
        }

        # TCP
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            st.session_state.protocol_count["TCP"] += 1
            log.update({
                "protocol": "TCP",
                "sport": tcp.sport,
                "dport": tcp.dport
            })

            if tcp.dport in suspicious_ports:
                log["alert"] = "Suspicious Port"

        # UDP
        elif packet.haslayer("UDP"):
            udp = packet["UDP"]
            st.session_state.protocol_count["UDP"] += 1
            log.update({
                "protocol": "UDP",
                "sport": udp.sport,
                "dport": udp.dport
            })

        # ICMP
        elif packet.haslayer("ICMP"):
            st.session_state.protocol_count["ICMP"] += 1
            log["protocol"] = "ICMP"

        # High traffic detection
        if st.session_state.ip_counter[src] > IP_THRESHOLD:
            log["alert"] = "High Traffic IP"

        st.session_state.logs.append(log)

# -----------------------------
# Capture Loop
# -----------------------------
if st.session_state.running:
    with st.spinner("Capturing packets..."):
        sniff(filter=protocol_filter, prn=process_packet, count=packet_limit)

# -----------------------------
# Data
# -----------------------------
df = pd.DataFrame(st.session_state.logs)

# -----------------------------
# Dashboard Layout
# -----------------------------
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Protocol Distribution")
    if st.session_state.protocol_count:
        fig, ax = plt.subplots()
        ax.bar(
            st.session_state.protocol_count.keys(),
            st.session_state.protocol_count.values()
        )
        ax.set_xlabel("Protocol")
        ax.set_ylabel("Count")
        st.pyplot(fig)

with col2:
    st.subheader("🌐 Top Active IPs")
    ip_df = pd.DataFrame(
        st.session_state.ip_counter.items(),
        columns=["IP", "Count"]
    ).sort_values(by="Count", ascending=False)

    st.dataframe(ip_df.head(), use_container_width=True)

# -----------------------------
# Packet Logs
# -----------------------------
st.subheader("📦 Packet Logs")
st.dataframe(df, use_container_width=True)

# -----------------------------
# Alerts
# -----------------------------
st.subheader("⚠️ Alerts")
alerts = df[df["alert"] != ""]

if not alerts.empty:
    st.dataframe(alerts, use_container_width=True)
else:
    st.success("No anomalies detected")

# -----------------------------
# ML Detection
# -----------------------------
st.subheader("🤖 ML-Based Anomaly Detection")

if len(df) > 10:
    try:
        features = df[["sport", "dport"]].fillna(0)

        model = IsolationForest(contamination=0.1)
        df["anomaly"] = model.fit_predict(features)

        anomalies = df[df["anomaly"] == -1]

        if not anomalies.empty:
            st.warning("Anomalies detected using ML")
            st.dataframe(anomalies, use_container_width=True)
        else:
            st.success("No ML anomalies detected")

    except Exception as e:
        st.write("ML processing skipped:", e)

# -----------------------------
# Download Logs
# -----------------------------
st.download_button(
    "⬇ Download Logs",
    df.to_csv(index=False),
    "network_logs.csv"
)