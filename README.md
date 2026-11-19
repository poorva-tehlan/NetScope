# NetScope — Network Traffic Monitoring & Protocol Analysis

**Computer Networks Mini-Project** | Python · Scapy · Streamlit · SQLite

NetScope is a Python-based network traffic monitoring and packet analysis application. It captures packets from a network interface, extracts protocol and connection metadata, stores live capture results locally, and presents interactive statistics in a Streamlit dashboard. It also supports offline PCAP analysis and a clearly labeled synthetic demo mode.

## Team Members

| S. No. | Name | Roll Number |
|:--:|---|---|
| 1 | *Shriya Jindal* | *2024UCA1889* |
| 2 | *Poorva Tehlan* | *2024UCA1891* |
| 3 | *Srishti* | *2024UCA1923* |
| 4 | *Geetu Sharma* | *2024UCA1937* |

**CSAI-2 | Semester-5**

**Course:** Computer Networks   
**Repository:** https://github.com/poorva-tehlan/NetScope/


## Project Overview

Traditional packet analyzers expose detailed network records that can be difficult for beginners to interpret at a glance. NetScope provides a focused, visual interface for understanding packet flows and protocol activity.

The application has three operating modes:

1. **Demo (synthetic):** Explore a sample dashboard without capturing real traffic. All sample records are simulated.
2. **Live capture (SQLite):** Capture real packets on a selected network interface using Scapy and Npcap (on Windows), store their metadata in SQLite, and explore the results in the dashboard.
3. **Upload PCAP:** Analyze an existing `.pcap` or `.pcapng` file (such as a capture exported from Wireshark) without starting a live collector.

### Features

- Packet sniffing of traffic visible to the selected interface
- Protocol identification: **TCP, UDP, DNS, ICMP, ARP**, and other traffic
- Source/destination IP addresses and TCP/UDP ports
- Packet timestamps, lengths, and brief summaries
- Traffic statistics, protocol distribution, timelines, and top communicating endpoints
- Protocol and IP-address filtering
- CSV export of filtered packet metadata
- Offline `.pcap` / `.pcapng` analysis (first 25,000 packets)
- **Best-effort website/service identification** based on visible DNS records or TLS Server Name Indication (SNI)
- Evidence fields (`hostname`, `service`, `evidence`) to clarify how a service was inferred

> **Website identification is not guaranteed.** Existing connections, DNS caching, encrypted DNS, QUIC, encrypted ClientHello, and shared hosting/CDNs can prevent accurate attribution. Unrecognized traffic is labeled **Unknown**; a service label does not establish the exact webpage visited.

## Architecture

```text
               Network interface (Wi-Fi / Ethernet)
                              |
                     Scapy live collector
                         (capture.py)
                              |
                Packet parsing + host tracking
                (packet_utils.py, attribution.py)
                              |
                      SQLite packet store
                       (storage.py)
                              |
                       Streamlit dashboard
                           (app.py)
                              |
                 Charts · Filters · Tables · CSV

Alternatives: synthetic traffic (demo_data.py) or uploaded PCAP
            ----------------> Streamlit dashboard
```

The collector and dashboard are **separate processes**. Keep `capture.py` running in one terminal while `app.py` runs in another for live capture.

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Programming language | Python | Packet processing and application logic |
| Packet capture and parsing | Scapy | Read network packets and extract metadata |
| Windows capture driver | Npcap | Enable live capture on Windows |
| Web dashboard | Streamlit | Interactive UI |
| Data manipulation | Pandas | Aggregation, filtering, and CSV export |
| Data storage | SQLite | Local persistent packet metadata for live mode |

## Getting Started — Clone and Run on Windows

The steps below use **Windows PowerShell in VS Code**. They do not require activating the virtual environment.

### 1. Install prerequisites

- **Python 3.11 or later:** https://www.python.org/downloads/ (select *Add Python to PATH* during installation if offered)
- **Npcap (for live capture on Windows):** https://npcap.com/#download

When installing Npcap, the default options are generally suitable. You can leave WinPcap compatibility mode unchecked. **Demo mode and offline PCAP analysis do not require Npcap.**

### 2. Clone the GitHub repository

Open VS Code, then choose **Terminal → New Terminal** and run:

```powershell
git clone https://github.com/poorva-tehlan/NetScope.git
cd NetScope
```

### 3. Create a virtual environment

```powershell
py -3.14 -m venv .venv 
```

Or, if the `py` launcher is unavailable:

```powershell
python -m venv .venv
```

The `.venv` folder is excluded from Git. You **do not need** to run `Activate.ps1`.

### 4. Install dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 5. Launch the dashboard (Terminal 1)

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL shown in the terminal (usually **http://localhost:8501**). Select **Demo (synthetic)** in the sidebar to confirm that the installation works. The dashboard will show simulated traffic statistics and charts.

### 6. Start live packet capture (Terminal 2)

**On Windows, install Npcap first.** In VS Code, click the **+** in the terminal panel to create a second PowerShell terminal in the same project directory. Leave Terminal 1 running.

List available network interfaces:

```powershell
.\.venv\Scripts\python.exe capture.py --list-interfaces
```

Start capture using Scapy's default interface:

```powershell
.\.venv\Scripts\python.exe capture.py
```

In the Streamlit dashboard, switch the sidebar source to **Live capture (SQLite)**. The collector writes packet metadata to `data/packets.sqlite3`; the dashboard reads it and refreshes its live view approximately every two seconds.

### 7. Generate traffic to verify capture (Terminal 3)

Open another VS Code terminal or PowerShell window:

```powershell
ping 1.1.1.1
nslookup example.com
```

Now look at the **ICMP** and **DNS** records in the dashboard. You can also open websites in your browser and examine additional TCP/UDP connections. Your results depend on the active interface, system and network configuration, and visible packet metadata.

If a relevant hostname is observable in DNS or TLS metadata, NetScope may label traffic as **YouTube**; otherwise it can correctly remain **Unknown**. NetScope cannot see encrypted webpage content.

### 8. Stop NetScope

- In Terminal 2, press **Ctrl+C** to stop the packet collector and flush pending records.
- In Terminal 1, press **Ctrl+C** to stop Streamlit.
- The locally saved SQLite database remains available for later inspection.

## Analyzing a PCAP / PCAPNG File

1. Start Streamlit using the command in Step 5.
2. Select **Upload PCAP** from the dashboard sidebar.
3. Choose a `.pcap` or `.pcapng` file created by Wireshark or another compatible packet capture tool.
4. Explore the protocol breakdown, packet table, filters, and other statistics.

For responsiveness, the application processes at most the **first 25,000 packets** from an uploaded capture. This is offline analysis; `capture.py` is not required.

## Project Structure

```text
NetScope/
├── app.py              # Streamlit dashboard, visualizations, PCAP upload
├── capture.py          # Real-time packet capture process
├── packet_utils.py     # Extract packet metadata and protocol information
├── attribution.py      # Best-effort DNS / TLS hostname and service attribution
├── storage.py          # SQLite connection, table schema, migrations
├── demo_data.py        # Synthetic sample traffic
├── requirements.txt    # Python dependencies
├── README.md           # Setup and project documentation
├── .gitignore          # Ignore virtual environment and generated data
├── .venv/              # Generated locally; not committed to Git
└── data/               # Generated locally; packet database not committed
```
