"""NetScope Streamlit dashboard: demo / live SQLite / uploaded PCAP."""
import io
import sqlite3
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from scapy.all import PcapReader
from packet_utils import packet_to_row, COLUMNS
from demo_data import make_demo
from attribution import HostTracker
from storage import DB

st.set_page_config(page_title="NetScope | Network Traffic Analytics", page_icon="🌐", layout="wide")
st.markdown("""<style>
.block-container {padding-top: 2rem; max-width: 1380px}
[data-testid="stMetric"] {border:1px solid #29354c; border-radius:12px; padding:15px}
</style>""", unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def demo():
    return make_demo()

@st.cache_data(show_spinner=False)
def parse_pcap(blob):
    result = []
    tracker = HostTracker()
    # Scapy's PcapReader requires a file-like stream; BytesIO avoids disk writes.
    with PcapReader(io.BytesIO(blob)) as reader:
        for i, pkt in enumerate(reader):
            if i >= 25000:  # bound memory use for classroom demo
                break
            row = packet_to_row(pkt)
            if row:
                host, service, evidence = tracker.observe(pkt)
                result.append((*row, host, service, evidence))
    return pd.DataFrame(result, columns=COLUMNS + ["hostname", "service", "evidence"])

def load_live():
    if not DB.exists():
        return pd.DataFrame(columns=COLUMNS)
    try:
        with sqlite3.connect(str(DB), timeout=5) as conn:
            # Most recent 25k packets only; safe even for long captures.
            df = pd.read_sql_query("SELECT timestamp, source, destination, protocol, source_port, destination_port, length, summary, hostname, service, evidence FROM (SELECT * FROM packets ORDER BY id DESC LIMIT 25000) ORDER BY id ASC", conn)
        return df
    except sqlite3.Error:
        return pd.DataFrame(columns=COLUMNS)

st.title("🌐 NetScope")
st.caption("Real-time traffic monitoring · Protocol analytics · Packet inspection")
source = st.sidebar.radio("Traffic source", ["Demo (synthetic)", "Live capture (SQLite)", "Upload PCAP"], index=0)
st.sidebar.markdown("---")
st.sidebar.info("Live capture: run `python capture.py` in another VS Code terminal. Capture only traffic you're allowed to inspect.")
if source == "Demo (synthetic)":
    st.warning("DEMO MODE: All packets shown here are synthetic examples, not real captured traffic.")
if source == "Upload PCAP":
    upload = st.file_uploader("Choose a .pcap or .pcapng capture", type=["pcap", "pcapng"])
    if upload is not None:
        try:
            upload_df = parse_pcap(upload.getvalue())
            st.success(f"Loaded {len(upload_df):,} packets (up to 25,000 analyzed).")
        except Exception as e:
            st.error(f"Could not read this capture: {e}")
            upload_df = pd.DataFrame(columns=COLUMNS)
    else:
        upload_df = pd.DataFrame(columns=COLUMNS)

protocol_selection = st.sidebar.multiselect("Protocol filter", ["TCP", "UDP", "DNS", "ICMP", "ARP", "OTHER"])
ip_query = st.sidebar.text_input("Filter source/destination IP (contains)", "")
st.sidebar.caption("Charts refresh every 2 seconds in live mode. CSV export uses current filters.")

@st.fragment(run_every="2s" if source == "Live capture (SQLite)" else None)
def dashboard():
    if source == "Demo (synthetic)":
        df = demo().copy()
    elif source == "Live capture (SQLite)":
        df = load_live()
        st.caption("Live capture database · updates every 2 seconds · most recent 25,000 packets")
    else:
        df = upload_df.copy()
    for col, default in (("hostname", ""), ("service", "Unknown"), ("evidence", "None")):
        if col not in df.columns:
            df[col] = default
        df[col] = df[col].fillna(default)
    if df.empty:
        st.info("No packets to display yet. Start the collector, choose Demo mode, or upload a PCAP.")
        return
    service_filter = st.session_state.get("service_filter", "All")
    if service_filter != "All":
        df = df[df["service"] == service_filter]
    if protocol_selection:
        df = df[df["protocol"].isin(protocol_selection)]
    if ip_query.strip():
        q = ip_query.strip()
        df = df[df["source"].astype(str).str.contains(q, regex=False, case=False) |
                df["destination"].astype(str).str.contains(q, regex=False, case=False)]
    if df.empty:
        st.info("No packets match the selected filters.")
        return
    df["length"] = pd.to_numeric(df["length"], errors="coerce").fillna(0).astype(int)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", f"{len(df):,}")
    c2.metric("Bytes observed", f"{df['length'].sum() / 1024:,.1f} KiB")
    c3.metric("Unique endpoint IPs", len(set(df["source"].dropna()) | set(df["destination"].dropna())))
    c4.metric("Most common protocol", str(df["protocol"].mode().iloc[0]))
    l, r = st.columns(2)
    with l:
        st.subheader("Protocol distribution")
        st.bar_chart(df["protocol"].value_counts().rename_axis("Protocol"), horizontal=True)
    with r:
        st.subheader("Packet rate over time")
        seconds = pd.to_datetime(df["timestamp"], errors="coerce").dt.floor("s")
        rate = df.groupby(seconds).size()
        rate.index.name = "Time"
        st.line_chart(rate.rename("Packets / second"))
    l2, r2 = st.columns(2)
    with l2:
        st.subheader("Top source IPs")
        st.bar_chart(df["source"].value_counts().head(8), horizontal=True)
    with r2:
        st.subheader("Traffic volume by protocol")
        st.bar_chart(df.groupby("protocol")["length"].sum().sort_values(ascending=False), horizontal=True)
    st.subheader("Website / service identification")
    st.caption("Names come from observed DNS answers or unencrypted TLS handshake hostnames (SNI). HTTPS content remains encrypted. DNS-over-HTTPS, QUIC, cached DNS, and shared CDNs may prevent accurate identification; Unknown does not mean suspicious.")
    identified = df[df["service"].ne("Unknown")]
    if identified.empty:
        st.info("No websites identified yet. Try opening a fresh website or run `nslookup youtube.com` while capture is running. DNS queries alone do not identify all subsequent connections.")
    else:
        a, b = st.columns(2)
        with a:
            st.bar_chart(identified["service"].value_counts().head(10), horizontal=True)
        with b:
            st.dataframe(identified.groupby(["service", "hostname"], dropna=False).size().rename("Packets").reset_index().sort_values("Packets", ascending=False).head(20), hide_index=True, use_container_width=True)
    st.subheader("Packet explorer")
    st.dataframe(df.iloc[::-1], use_container_width=True, hide_index=True, height=350)
    st.download_button("⬇ Export filtered packets (CSV)", data=df.to_csv(index=False).encode("utf-8"),
                       file_name="netscope_packets.csv", mime="text/csv", key="export_csv")
    st.caption("Packet lengths represent observed network-layer/frame bytes, not precise application throughput. Only packet metadata is stored; no payloads are recorded.")

dashboard()
