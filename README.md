# Encrypted Traffic Threat Analyzer

A local research prototype for exploring suspicious behavior in encrypted network traffic using packet-flow metadata. It does not decrypt traffic.

## Run locally

1. Install Python 3.10 or newer.
2. Open a terminal in this folder and install the listed packages:

   ```
   python -m pip install -r requirements.txt
   ```

3. Start the app:

   ```
   python -m streamlit run app.py
   ```

The app opens in a local browser. Uploaded files are processed by the local app process. Avoid exposing the app to a network you do not control.

The project settings disable Streamlit usage statistics and bind the server to `127.0.0.1` so it is available only on this computer.

## Inputs

- **PCAP / PCAPNG:** IP packet captures. Scapy groups packets into bidirectional flows and extracts packet sizes, timing, byte counts, direction counts, and TCP flags. Payloads are not decoded.
- **Labeled flow CSV:** One row per flow, with numeric feature columns and a label column such as `label`, `class`, `attack_type`, or `target`. The training page evaluates a Random Forest on a held-out split.
- **Unlabeled flow CSV:** Numeric feature columns for Isolation Forest anomaly screening. If a supervised model has been trained in the current app session, this page can also score a new compatible CSV.

`flow_csv_template.csv` shows the expected column names for a labeled flow dataset. It is a header-only template, not a traffic dataset.

## Synthetic demo files

- `demo_labeled_flows.csv`: 1,000 fabricated labeled flow rows for trying the Random Forest training and evaluation workflow.
- `demo_unlabeled_flows.csv`: 280 fabricated rows for trying anomaly screening.
- `demo_encrypted_traffic.pcap`: fabricated Ethernet/IPv4/TCP packets with TLS-like payload bytes for trying the PCAP upload workflow. It is not captured from a real network and does not contain a valid TLS session.

These samples are designed to exercise the interface. Do not cite their results as evidence of detection performance or use them as a substitute for a documented research dataset.

The app caps individual uploads at 200 MB in this prototype.

## Live monitoring on Windows

The **Live monitor** page can watch one network interface while the app is open. It summarizes IP/TCP/UDP flow metadata in memory, refreshes the view every two seconds, and stops at the selected time limit. After 30 flows, a rolling Isolation Forest ranks unusual combinations in the newest 500 flows; explicit rules also flag multi-port connections, large outbound flows, and short high-volume flows. If a labeled classifier was trained in the same app session, it can score the live flows too. The monitor does not save PCAPs, retain payload bytes, decrypt TLS, or inspect application content.

1. Install [Npcap](https://npcap.com/#download) if it is not already installed. Scapy's Windows capture support relies on Npcap.
2. Open **Windows Terminal** as administrator.
3. Change to this project folder and run `run_windows.bat`.
4. In the app, choose **Live monitor**, select your active Wi-Fi or Ethernet interface, and start capture.

Live capture can require administrator privileges on Windows. The Streamlit server is configured to bind only to `127.0.0.1`, so the elevated app is reachable from this computer only. Stop monitoring from the page when you finish; it also stops automatically after the configured limit (up to one hour).

Live alerts combine review rules for multi-port connections, high outbound flow volume, and high packet volume with rolling Isolation Forest outlier scores. A supervised model trained in the current session can add predictions. These methods can miss threats and can flag ordinary activity. A trained model's results depend on its labels and data quality. This is a research prototype, not endpoint protection or a production IDS.

## Interpretation

Offline Isolation Forest flags flows that look unusual relative to the uploaded capture; live Isolation Forest compares recent flows in a rolling window. Neither establishes that a flow is malicious. Supervised results depend on the dataset, labels, and split design. For thesis-quality evaluation, document the dataset source and license, use capture-based or time-based holdouts where possible, and report class balance, precision, recall, and false positives.

Live monitor direction estimates use IP address ranges and can be ambiguous on VPNs, carrier-grade NAT, and some virtual adapters.

Use only captures and datasets you are authorized to analyze. This app is a student research prototype, not a production detection system.

