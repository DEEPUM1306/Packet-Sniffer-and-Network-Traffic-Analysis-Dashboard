import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
import tempfile

# -------------------------------
# PAGE CONFIG nmap -sS localhost
# -------------------------------
st.set_page_config(
    page_title="Packet Sniffer",
    page_icon="📡",
    layout="wide"
)

st.title("📡 Packet Sniffing and Traffic Analysis")
st.caption("Analyze network traffic using protocol, ports, and packet behavior")

# -------------------------------
# SIDEBAR
# -------------------------------
menu = st.sidebar.radio(
    "Navigation",
    ["Live Capture", "Upload PCAP", "Traffic Dashboard", "Download Report"]
)

# Filters
st.sidebar.subheader("Filters")
protocol_filter = st.sidebar.multiselect(
    "Select Protocol",
    ["TCP", "UDP", "ICMP", "ARP", "Other"],
    default=["TCP","UDP","ICMP","ARP","Other"]
)

# -------------------------------
# SESSION STATE
# -------------------------------
if "df" not in st.session_state:
    st.session_state.df = None

# -------------------------------
# PACKET PROCESSING
# -------------------------------
def process_packets(packets):
    data = []

    for pkt in packets:
        proto = "Other"
        src = "Unknown"
        dst = "Unknown"
        port = 0

        # IP Layer
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst

        # ARP FIX
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst

        # Protocol Detection
        if pkt.haslayer(TCP):
            proto = "TCP"
            port = pkt[TCP].dport

        elif pkt.haslayer(UDP):
            proto = "UDP"
            port = pkt[UDP].dport

        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        length = len(pkt)

        data.append([src, dst, proto, port, length])

    df = pd.DataFrame(
        data,
        columns=["src_ip","dst_ip","protocol","port","length"]
    )
    return df

# -------------------------------
# LIVE CAPTURE
# -------------------------------
if menu == "Live Capture":
    st.header("Live Packet Capture")

    duration = st.slider("Capture Duration (seconds)", 5, 60, 15)

    if st.button("Start Capture"):
        st.warning("Capturing packets...")
        packets = sniff(timeout=duration)
        df = process_packets(packets)

        st.session_state.df = df
        st.success(f"{len(df)} packets captured")
        st.dataframe(df)

# -------------------------------
# PCAP UPLOAD
# -------------------------------
if menu == "Upload PCAP":
    st.header("Upload Wireshark File")

    file = st.file_uploader("Upload .pcap/.pcapng", type=["pcap","pcapng"])

    if file:
        temp = tempfile.NamedTemporaryFile(delete=False)
        temp.write(file.read())

        packets = rdpcap(temp.name)
        df = process_packets(packets)

        st.session_state.df = df
        st.success("File Loaded Successfully")
        st.dataframe(df)

# -------------------------------
# DASHBOARD
# -------------------------------
if menu == "Traffic Dashboard":
    if st.session_state.df is None:
        st.info("Capture or upload packets first")
    else:
        df = st.session_state.df.copy()

        # Apply filter
        df = df[df["protocol"].isin(protocol_filter)]

        st.header("Traffic Analysis Dashboard")

        # -------------------------------
        # METRICS
        # -------------------------------
        col1, col2, col3 = st.columns(3)

        col1.metric("Total Packets", len(df))
        col2.metric("Unique Source IPs", df["src_ip"].nunique())
        col3.metric("Unique Dest IPs", df["dst_ip"].nunique())

        # -------------------------------
        # TOP SOURCE IPs
        # -------------------------------
        top_src = df["src_ip"].value_counts().reset_index()
        top_src.columns = ["IP","Packets"]

        fig1 = px.bar(top_src, x="IP", y="Packets", title="Top Source IPs")
        st.plotly_chart(fig1)

        # -------------------------------
        # PROTOCOL DISTRIBUTION
        # -------------------------------
        fig2 = px.pie(df, names="protocol", title="Protocol Distribution")
        st.plotly_chart(fig2)

        # -------------------------------
        # PORT ANALYSIS
        # -------------------------------
        fig3 = px.histogram(df, x="port", title="Port Distribution")
        st.plotly_chart(fig3)

        # -------------------------------
        # PACKET SIZE
        # -------------------------------
        fig4 = px.histogram(df, x="length", title="Packet Size Distribution")
        st.plotly_chart(fig4)

        # -------------------------------
        # SUSPICIOUS DETECTION
        # -------------------------------
        st.subheader("⚠️ Suspicious Traffic")

        suspicious = df.groupby("src_ip").agg({
            "port":"nunique",
            "length":"count"
        }).reset_index()

        suspicious.columns = ["src_ip","unique_ports","packet_count"]

        alerts = suspicious[
            (suspicious["unique_ports"] > 10) |
            (suspicious["packet_count"] > 200)
        ]

        if len(alerts) > 0:
            st.error("Suspicious Activity Detected")
            st.dataframe(alerts)
        else:
            st.success("No suspicious traffic")

        # -------------------------------
        # RAW DATA
        # -------------------------------
        st.subheader("Captured Packet Data")
        st.dataframe(df)

# -------------------------------
# DOWNLOAD REPORT
# -------------------------------
if menu == "Download Report":
    if st.session_state.df is None:
        st.info("No data to download")
    else:
        df = st.session_state.df.copy()

        # APPLY SAME FILTER AS DASHBOARD
        df = df[df["protocol"].isin(protocol_filter)]

        if df.empty:
            st.warning("No data available for selected protocol")
        else:
            csv = df.to_csv(index=False).encode()

            st.download_button(
                label="Download Filtered Traffic Report",
                data=csv,
                file_name="filtered_traffic_report.csv",
                mime="text/csv"
            )