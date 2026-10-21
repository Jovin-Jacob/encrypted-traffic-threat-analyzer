from __future__ import annotations

import io
import ipaddress
import math
import statistics
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    # Import through scapy.all so Scapy registers Ethernet/IP layer decoders
    # before PcapReader tries to decode classic Ethernet PCAP files.
    from scapy.all import PcapReader
except ImportError:
    PcapReader = None


st.set_page_config(page_title="Encrypted Traffic Threat Analyzer", page_icon="◈", layout="wide")
st.markdown("""
<style>
:root { --ink:#f2edff; --muted:#b2a8c8; --line:#302743; --purple:#a855f7; --neon:#e879f9; --canvas:#0c0a12; --panel:#15121d; }
html, body, [class*="css"] { font-family:'Segoe UI',Arial,sans-serif; color:var(--ink); }
.stApp, [data-testid="stAppViewContainer"] { background:var(--canvas); color:var(--ink); }
.block-container { max-width:1480px; padding-top:2rem; padding-bottom:3rem; }
header[data-testid="stHeader"] { background:rgba(12,10,18,.92); }
h1,h2,h3,h4 { font-family:'Segoe UI',Arial,sans-serif; letter-spacing:-.025em; color:var(--ink) !important; }
h2 { margin-top:1rem; }
p, label, [data-testid="stWidgetLabel"] p, [data-testid="stCaptionContainer"] { color:#d7d0e5; }
[data-testid="stMarkdownContainer"] { color:var(--ink); }
.brandbar { display:flex; align-items:center; gap:10px; margin:0 0 .9rem; color:#c4b5fd; font-size:.75rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
.brandmark { display:grid; place-items:center; width:34px; height:34px; border-radius:11px; background:#26173b; color:#e879f9; font-size:1.25rem; box-shadow:0 0 18px #a855f744; }
.local-tag { margin-left:auto; display:inline-flex; align-items:center; gap:7px; border:1px solid #4b2866; border-radius:999px; background:#1b1226; color:#e9a8ff; padding:7px 11px; letter-spacing:.04em; font-size:.7rem; }
.local-dot { width:7px; height:7px; border-radius:50%; background:#5cf2b4; box-shadow:0 0 10px #5cf2b4; }
.hero { position:relative; overflow:hidden; padding:1.4rem 1.75rem; border:1px solid #493065; border-radius:18px; color:white; background:radial-gradient(ellipse at 88% 0%,rgba(168,85,247,.27),transparent 38%),linear-gradient(115deg,#171224 0%,#21162f 54%,#24143b 100%); margin-bottom:1rem; box-shadow:0 14px 40px #0005, inset 0 1px #ffffff0c; }
.hero h1 { font-family:'Segoe UI',Arial,sans-serif; letter-spacing:-.04em; font-size:clamp(1.7rem,2.5vw,2.25rem); line-height:1.12; margin:0 0 .4rem; color:#fff !important; }
.hero p { color:#d9cee9 !important; margin:0; max-width:800px; font-size:1rem; line-height:1.6; }
.hero-kicker { color:#e879f9; text-transform:uppercase; letter-spacing:.14em; font-size:.69rem; font-weight:700; margin-bottom:.45rem; }
.note { border:1px solid #332742; border-left:4px solid #c026d3; border-radius:12px; background:#15121d; padding:12px 16px; color:#d8d0e6; line-height:1.55; margin:0 0 1rem; }
.note b { color:#f0abfc; }
.section-intro { color:#b9aecb !important; margin-top:-.35rem; margin-bottom:1rem; }
div[data-testid="stButton"] > button[kind="secondary"] { color:#e6ddf2 !important; background:#17131f !important; border:1px solid #382b4b !important; }
div[data-testid="stButton"] > button[kind="secondary"]:hover { color:#fff !important; border-color:#c026d3 !important; background:#241831 !important; box-shadow:0 0 18px #c026d333; }
div[data-testid="stButton"] > button[kind="primary"] { color:#fff !important; background:linear-gradient(110deg,#7e22ce,#c026d3) !important; border:1px solid #d946ef !important; box-shadow:0 0 16px #c026d344; }
div[data-testid="stButton"] > button[kind="primary"]:hover { background:linear-gradient(110deg,#9333ea,#d946ef) !important; box-shadow:0 0 24px #d946ef66; }
div[data-testid="stMetric"] { background:linear-gradient(145deg,#191522,#14111b); border:1px solid #332742; padding:16px 17px; border-radius:14px; box-shadow:0 8px 24px #0003; }
div[data-testid="stMetricLabel"] { color:#bdb2cf !important; font-size:.82rem; }
div[data-testid="stMetricValue"] { color:#f5edff !important; font-family:'Segoe UI',Arial,sans-serif; font-weight:700; }
div[data-testid="stFileUploader"] section { border:1px dashed #67448a; border-radius:14px; background:#15121d; }
div[data-testid="stFileUploader"] section:hover { border-color:#e879f9; background:#1b1425; }
div[data-testid="stFileUploader"] section *, [data-testid="stWidgetLabel"] *, [data-testid="stSlider"] * { color:#e8e0f2 !important; }
div[data-testid="stDataFrame"] { border:1px solid #332742; border-radius:12px; overflow:hidden; }
div[data-testid="stDataFrame"] iframe { background:#15121d; }
div[data-testid="stSelectbox"] [data-baseweb="select"] > div, div[data-testid="stTextInput"] input, div[data-testid="stNumberInput"] input { color:#f2edff; background:#17131f; border-color:#40314f; }
div[data-testid="stSlider"] [data-testid="stThumbValue"] { color:#f0abfc !important; }
div.stButton > button, div.stDownloadButton > button { border-radius:10px; font-weight:600; min-height:2.65rem; transition:all .15s ease; }
div[data-testid="stDownloadButton"] > button { color:#f4eaff !important; background:#21182e !important; border:1px solid #533a6d !important; }
div[data-testid="stDownloadButton"] > button:hover { border-color:#e879f9 !important; box-shadow:0 0 16px #c026d333; }
div[data-testid="stAlert"] { border-radius:12px; background:#17131f; }
details { border-radius:12px !important; background:#15121d; }
@media (max-width:760px) { .block-container { padding:1.4rem 1rem 2rem; } .hero { padding:1.2rem; } }
</style>
""", unsafe_allow_html=True)

FEATURE_COLUMNS = [
    "duration_seconds", "packet_count", "total_bytes", "forward_packets",
    "reverse_packets", "forward_bytes", "reverse_bytes", "mean_packet_size",
    "std_packet_size", "mean_interarrival_seconds", "payload_bytes",
    "syn_count", "ack_count", "rst_count", "fin_count",
]
NON_FEATURE_COLUMNS = {
    "label", "flow_id", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "start_time", "end_time", "timestamp",
}


def _endpoint(packet, ip_layer):
    src = packet[ip_layer].src
    dst = packet[ip_layer].dst
    if packet.haslayer("TCP"):
        sport, dport, proto = int(packet["TCP"].sport), int(packet["TCP"].dport), "TCP"
    elif packet.haslayer("UDP"):
        sport, dport, proto = int(packet["UDP"].sport), int(packet["UDP"].dport), "UDP"
    else:
        sport = dport = 0
        proto = str(getattr(packet[ip_layer], "proto", "IP"))
    return (str(src), sport), (str(dst), dport), proto


def extract_pcap(uploaded_file):
    """Aggregate a PCAP into bidirectional flow metadata without decoding payloads."""
    if PcapReader is None:
        raise RuntimeError("Scapy is missing. Install the packages listed in requirements.txt.")
    data = uploaded_file.getvalue()
    reader = PcapReader(io.BytesIO(data))
    flows = {}
    packets_read = 0
    ip_packets_used = 0
    try:
        for packet in reader:
            packets_read += 1
            ip_layer = "IP" if packet.haslayer("IP") else "IPv6" if packet.haslayer("IPv6") else None
            if not ip_layer:
                continue
            ip_packets_used += 1
            a, b, proto = _endpoint(packet, ip_layer)
            left, right = sorted((a, b))
            key = (left, right, proto)
            ts = float(packet.time)
            plen = int(len(packet))
            payload_len = len(bytes(packet["Raw"].load)) if packet.haslayer("Raw") else 0
            item = flows.get(key)
            if item is None:
                item = {"source_ip": left[0], "source_port": left[1],
                        "destination_ip": right[0], "destination_port": right[1],
                        "protocol": proto, "start_time": ts, "end_time": ts,
                        "packet_times": [], "packet_sizes": [], "forward_packets": 0,
                        "reverse_packets": 0, "forward_bytes": 0, "reverse_bytes": 0,
                        "payload_bytes": 0, "syn_count": 0, "ack_count": 0,
                        "rst_count": 0, "fin_count": 0}
                flows[key] = item
            forward = (a == left)
            item["start_time"] = min(item["start_time"], ts)
            item["end_time"] = max(item["end_time"], ts)
            item["packet_times"].append(ts)
            item["packet_sizes"].append(plen)
            item["payload_bytes"] += payload_len
            direction = "forward" if forward else "reverse"
            item[f"{direction}_packets"] += 1
            item[f"{direction}_bytes"] += plen
            if packet.haslayer("TCP"):
                flags = str(packet["TCP"].flags)
                item["syn_count"] += int("S" in flags)
                item["ack_count"] += int("A" in flags)
                item["rst_count"] += int("R" in flags)
                item["fin_count"] += int("F" in flags)
    finally:
        reader.close()

    rows = []
    for item in flows.values():
        times, sizes = item.pop("packet_times"), item.pop("packet_sizes")
        ordered = sorted(times)
        intervals = np.diff(ordered) if len(ordered) > 1 else []
        item["duration_seconds"] = max(0.0, item["end_time"] - item["start_time"])
        item["packet_count"] = len(sizes)
        item["total_bytes"] = sum(sizes)
        item["mean_packet_size"] = float(np.mean(sizes)) if sizes else 0.0
        item["std_packet_size"] = float(np.std(sizes)) if sizes else 0.0
        item["mean_interarrival_seconds"] = float(np.mean(intervals)) if len(intervals) else 0.0
        rows.append(item)
    df = pd.DataFrame(rows)
    if not df.empty:
        df["flow_id"] = [f"F-{i:05d}" for i in range(1, len(df) + 1)]
    df.attrs["packets_read"] = packets_read
    df.attrs["ip_packets_used"] = ip_packets_used
    return df


def recommendations(results, suspicious_mask):
    tips = []
    flagged = results.loc[suspicious_mask]
    if flagged.empty:
        return ["No flows were flagged by this model. Review coverage and labels before treating this as evidence that the capture is safe."]
    source_port_counts = flagged.groupby("source_ip")["destination_port"].nunique() if "source_ip" in flagged else pd.Series(dtype=float)
    scanners = source_port_counts[source_port_counts >= 8]
    if len(scanners):
        for ip, count in scanners.head(3).items():
            tips.append(f"Review {ip}: its flagged flows contacted {count} distinct destination ports. Confirm whether this matches approved scanning or inventory activity.")
    if "total_bytes" in flagged and not results.empty:
        cutoff = results["total_bytes"].quantile(.95)
        high_volume = flagged[flagged["total_bytes"] >= cutoff]
        if len(high_volume):
            tips.append("Inspect the high-volume flagged flows and correlate them with endpoint and proxy logs; unusual transfer volume alone does not prove exfiltration.")
    if "destination_port" in flagged and (flagged["destination_port"] == 53).any():
        tips.append("Review DNS activity against your resolver logs, especially repeated or unusually large queries.")
    tips.extend([
        "Validate alerts against firewall, DNS, endpoint, and authentication logs before responding.",
        "If a flow is expected, add context or labels and rerun evaluation; this detector can produce false positives.",
    ])
    return tips[:5]


def supervised_recommendations(scored):
    tips = []
    predicted = scored["predicted_label"].astype(str)
    known_benign = {"benign", "normal", "legitimate", "clean", "safe"}
    counts = predicted.value_counts()
    flagged = counts[[name for name in counts.index if name.strip().lower() not in known_benign]]
    if flagged.empty:
        tips.append("The model did not predict a non-benign class using the recognized label names. Confirm that your dataset's labels are mapped correctly before interpreting this as a clean result.")
    else:
        for label, count in flagged.head(4).items():
            tips.append(f"The model predicted {count:,} flow(s) as '{label}'. Validate a sample against ground truth and supporting network logs before taking action.")
    if "model_confidence" in scored and len(scored):
        low_confidence = int((scored["model_confidence"] < .65).sum())
        if low_confidence:
            tips.append(f"{low_confidence:,} prediction(s) have confidence below 0.65; prioritize label review and avoid automated response.")
    tips.append("Check for label imbalance and train/test leakage; confidence is not a probability that an event is malicious.")
    return tips


def assess_live_flows(frame, transfer_threshold_mb=5):
    """Apply explicit, review-only heuristics to current flow metadata."""
    result = frame.copy()
    scores = pd.Series(0, index=result.index, dtype=int)
    reasons = {idx: [] for idx in result.index}
    recent_cutoff = datetime.now(timezone.utc).timestamp() - 600
    recent = result[result["end_time"] >= recent_cutoff] if "end_time" in result else result
    scan_counts = {}
    if {"internal_ip", "remote_port", "direction"}.issubset(recent.columns):
        outbound = recent[recent["direction"] == "outgoing"]
        scan_counts = outbound.groupby("internal_ip")["remote_port"].nunique().to_dict()

    byte_threshold = float(transfer_threshold_mb) * 1024 * 1024
    for idx, row in result.iterrows():
        source = row.get("internal_ip", "")
        port_count = int(scan_counts.get(source, 0))
        if row.get("direction") == "outgoing" and port_count >= 10:
            scores.loc[idx] += 70
            reasons[idx].append(f"Possible port scanning: {source} contacted {port_count} destination ports in the current capture window")
        outbound_bytes = float(row.get("outbound_bytes", 0))
        inbound_bytes = float(row.get("inbound_bytes", 0))
        if row.get("direction") == "outgoing" and outbound_bytes >= byte_threshold and float(row.get("duration_seconds", 0)) >= 5:
            scores.loc[idx] += 65
            reasons[idx].append(f"High outbound flow volume: {outbound_bytes / (1024 * 1024):.1f} MiB")
        elif row.get("direction") == "outgoing" and outbound_bytes >= 1024 * 1024 and outbound_bytes > max(1, inbound_bytes) * 12:
            scores.loc[idx] += 30
            reasons[idx].append("Outbound bytes greatly exceed inbound bytes")
        if int(row.get("packet_count", 0)) >= 500 and float(row.get("duration_seconds", 0)) <= 10:
            scores.loc[idx] += 45
            reasons[idx].append("High packet volume within a short flow")

    result["risk_score"] = scores.clip(upper=100)
    result["alert"] = np.where(result["risk_score"] >= 50, "Review", "No rule triggered")
    result["alert_reason"] = ["; ".join(reasons[idx]) for idx in result.index]
    return result


def score_live_with_trained_model(frame, model, feature_names):
    result = frame.copy()
    X = clean_for_model(result, feature_names)
    predicted = model.predict(X)
    result["model_prediction"] = predicted.astype(str)
    confidence = model.predict_proba(X).max(axis=1) if hasattr(model, "predict_proba") else np.ones(len(result))
    result["model_confidence"] = confidence
    benign = {"benign", "normal", "legitimate", "clean", "safe"}
    model_flags = [str(label).strip().lower() not in benign and float(conf) >= .65
                   for label, conf in zip(predicted, confidence)]
    for idx, flagged in zip(result.index, model_flags):
        if flagged:
            current = int(result.at[idx, "risk_score"])
            result.at[idx, "risk_score"] = max(current, 75)
            reason = f"Trained model predicted '{result.at[idx, 'model_prediction']}' ({result.at[idx, 'model_confidence']:.0%} confidence)"
            existing = result.at[idx, "alert_reason"]
            result.at[idx, "alert_reason"] = f"{existing}; {reason}" if existing else reason
            result.at[idx, "alert"] = "Review"
    return result


def score_live_anomalies(frame):
    """Fit a lightweight rolling-window outlier model on recent live flows."""
    result = frame.copy()
    result["anomaly_score"] = np.nan
    result["ml_anomaly"] = False
    feature_names = [name for name in FEATURE_COLUMNS if name in result.columns]
    if len(result) < 30 or len(feature_names) < 2:
        return result
    recent_indices = result.head(500).index
    X = clean_for_model(result.loc[recent_indices], feature_names)
    X = X.loc[:, X.notna().any()]
    if X.shape[1] < 2:
        return result
    X = X.fillna(X.median()).fillna(0)
    model = IsolationForest(n_estimators=100, contamination=0.03, random_state=42, n_jobs=1)
    prediction = model.fit_predict(X)
    result.loc[recent_indices, "anomaly_score"] = -model.score_samples(X)
    result.loc[recent_indices, "ml_anomaly"] = prediction == -1
    for idx in result.index[recent_indices][prediction == -1]:
        result.at[idx, "risk_score"] = max(int(result.at[idx, "risk_score"]), 55)
        reason = "Unusual combination of flow features in the recent traffic window (Isolation Forest)"
        existing = result.at[idx, "alert_reason"]
        result.at[idx, "alert_reason"] = f"{existing}; {reason}" if existing else reason
        result.at[idx, "alert"] = "Review"
    return result


def capture_interfaces():
    try:
        from scapy.all import conf, get_if_list
        result = []
        for name in get_if_list():
            label = name
            try:
                device = conf.ifaces.dev_from_name(name)
                description = getattr(device, "description", None)
                address = getattr(device, "ip", None)
                extras = [v for v in (description, address) if v and str(v) not in name]
                if extras:
                    label = f"{name} · {' · '.join(map(str, extras))}"
            except Exception:
                pass
            result.append((label, name))
        return result
    except Exception:
        return []


def numeric_features(frame, target=None):
    ignored = NON_FEATURE_COLUMNS | ({target} if target else set())
    cols = [c for c in frame.columns if c not in ignored and pd.api.types.is_numeric_dtype(frame[c])]
    return cols


def clean_for_model(frame, columns):
    X = frame.reindex(columns=columns).copy()
    for col in X:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    return X


def main():
    st.markdown('<div class="brandbar"><span class="brandmark">◈</span><span>Traffic Lab</span><span class="local-tag"><i class="local-dot"></i>LOCAL · PRIVACY FIRST</span></div>', unsafe_allow_html=True)
    st.markdown('<div class="hero"><div class="hero-kicker">Network security workspace</div><h1>Encrypted Traffic Threat Analyzer</h1><p>Investigate unusual network behavior from packet-flow metadata. Analyze a capture, monitor a local interface, or evaluate a model with labeled flows.</p></div>', unsafe_allow_html=True)
    st.markdown('<div class="note"><b>Privacy and interpretation:</b> This tool does not decrypt encrypted sessions. It analyzes flow metadata such as packet sizes, timing, ports, and TCP flags. An alert is a lead for investigation, not proof of an attack.</div>', unsafe_allow_html=True)

    sections = ["Analyze traffic", "Live monitor", "Train with labels", "About this project"]
    if "workspace_section" not in st.session_state:
        st.session_state["workspace_section"] = sections[0]
    nav_columns = st.columns(4, gap="small")
    for index, name in enumerate(sections):
        if nav_columns[index].button(
            name,
            key=f"workspace_nav_{index}",
            type="primary" if st.session_state["workspace_section"] == name else "secondary",
            use_container_width=True,
        ):
            st.session_state["workspace_section"] = name
            st.rerun()
    section = st.session_state["workspace_section"]
    section_copy = {
        "Analyze traffic": "Review an offline PCAP, PCAPNG, or flow CSV and download ranked findings.",
        "Live monitor": "Summarize traffic on a local interface and surface flows that may need review.",
        "Train with labels": "Measure a supervised model with labeled flow data, then score new flows.",
        "About this project": "Understand what the analyzer can see, how it works, and where its limits are.",
    }
    st.markdown(f'<div class="section-intro">{section_copy[section]}</div>', unsafe_allow_html=True)

    if section == "Analyze traffic":
        st.subheader("Analyze an offline capture")
        col1, col2 = st.columns([2, 1])
        with col1:
            capture = st.file_uploader("Upload a packet capture or flow CSV", type=["pcap", "pcapng", "csv"], help="PCAP and PCAPNG are converted to bidirectional flow metadata. CSV should contain numeric flow features; an optional label column enables supervised evaluation.")
        with col2:
            contamination = st.slider("Expected anomaly share", min_value=0.01, max_value=0.20, value=0.05, step=0.01, help="Used only by Isolation Forest. This is a tuning assumption, not a measured attack rate.")
        if capture:
            try:
                analysis_started = time.perf_counter()
                if capture.size > 200 * 1024 * 1024:
                    st.error("This first version supports files up to 200 MB.")
                    return
                if capture.name.lower().endswith(".csv"):
                    flows = pd.read_csv(capture)
                    source_kind = "CSV flow data"
                    packets_read = ip_packets_used = None
                else:
                    with st.spinner("Extracting bidirectional flows from capture…"):
                        flows = extract_pcap(capture)
                    packets_read = flows.attrs.get("packets_read", 0)
                    ip_packets_used = flows.attrs.get("ip_packets_used", 0)
                    source_kind = "PCAP flow metadata"
                if flows.empty:
                    st.warning("No IP flows were found in this file.")
                    return
                feature_cols = numeric_features(flows)
                if len(feature_cols) < 2:
                    st.error("Need at least two numeric flow features to run anomaly detection. Check your CSV columns or upload a packet capture.")
                    return
                X = clean_for_model(flows, feature_cols)
                X = X.loc[:, X.notna().any()]
                X = X.fillna(X.median()).fillna(0)
                model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
                predictions = model.fit_predict(X)
                scores = -model.score_samples(X)
                analysis_seconds = time.perf_counter() - analysis_started
                flows["anomaly_score"] = scores
                flows["detection"] = np.where(predictions == -1, "Review", "No anomaly flagged")
                suspicious = predictions == -1
                st.session_state["last_results"] = flows
                st.session_state["last_suspicious"] = suspicious
                st.session_state["last_source"] = source_kind
                st.markdown("### Results")
                metrics = st.columns(4)
                metrics[0].metric("Packets read", f"{packets_read:,}" if packets_read is not None else "—")
                metrics[1].metric("IP packets used", f"{ip_packets_used:,}" if ip_packets_used is not None else "—")
                metrics[2].metric("Flows analyzed", f"{len(flows):,}")
                metrics[3].metric("Analysis time", f"{analysis_seconds:.2f} sec")
                detail_metrics = st.columns(3)
                detail_metrics[0].metric("Flagged for review", f"{int(suspicious.sum()):,}")
                detail_metrics[1].metric("Features used", f"{X.shape[1]}")
                detail_metrics[2].metric("Capture size", f"{capture.size / (1024 * 1024):.2f} MB")
                packet_summary = (
                    f"{packets_read:,} capture packets were read; {ip_packets_used:,} IPv4/IPv6 packets contributed to flows."
                    if packets_read is not None
                    else "For CSV uploads, packet totals are unavailable because each row represents a flow."
                )
                st.caption(
                    f"Elapsed time covers file parsing, flow preparation, and Isolation Forest fitting/scoring. "
                    f"{packet_summary} Isolation Forest was fitted to {len(flows):,} flows using "
                    f"{X.shape[1]} features. Review share is configured as {contamination:.0%}; "
                    "this is unsupervised anomaly screening, not a validated attack classifier."
                )
                show_cols = [c for c in ["flow_id", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "packet_count", "total_bytes", "duration_seconds", "anomaly_score", "detection"] if c in flows]
                st.dataframe(flows.sort_values("anomaly_score", ascending=False)[show_cols], use_container_width=True, hide_index=True)
                st.download_button("Download results as CSV", data=flows.to_csv(index=False).encode("utf-8"), file_name="traffic_analysis_results.csv", mime="text/csv")
                st.markdown("### Investigation recommendations")
                for tip in recommendations(flows, suspicious):
                    st.markdown(f"- {tip}")
                with st.expander("How to read these results"):
                    st.write("Anomaly scores rank flows by how unusual they look relative to the uploaded file. Since there are no ground-truth labels in a plain capture, the model cannot tell you that an alert is a specific attack. Use the labelled-data workflow to measure precision, recall, and F1 on known examples.")
            except Exception as exc:
                st.error(f"Could not analyze this file: {exc}")
                st.info("For PCAP files, check that the capture is valid. For CSV, use one row per flow and numeric columns for measurements.")
        else:
            st.markdown("#### What you can upload")
            a, b = st.columns(2)
            a.info("**PCAP / PCAPNG**\n\nCaptured IP packets. The app groups packets into bidirectional flows and extracts metadata locally.")
            b.info("**CSV flow dataset**\n\nOne row per flow with numeric measurements. A `label` column is optional here; use the training page to evaluate labeled data.")
            st.markdown("#### Try the synthetic examples")
            sample_dir = Path(__file__).resolve().parent
            d1, d2 = st.columns(2)
            d1.download_button("Download sample PCAP", (sample_dir / "demo_encrypted_traffic.pcap").read_bytes(), "demo_encrypted_traffic.pcap", "application/vnd.tcpdump.pcap", help="Fabricated packet data for testing the upload and anomaly workflow; not a real capture.")
            d2.download_button("Download sample flow CSV", (sample_dir / "demo_unlabeled_flows.csv").read_bytes(), "demo_unlabeled_flows.csv", "text/csv", help="Fabricated flow records for testing anomaly screening.")
            st.caption("Synthetic examples are only for exercising the interface. Do not use their model scores as research results.")

    elif section == "Live monitor":
        st.subheader("Monitor this computer's network traffic")
        st.write("Capture metadata from one network interface and review possible scanning, unusually large outbound flows, and high-rate flows. The monitor does not save packet captures or packet contents.")
        st.info("On Windows, live capture requires Npcap. If capture cannot start, close this app and relaunch it as administrator. The monitor stops automatically at the selected time limit.")
        interfaces = capture_interfaces()
        monitor = st.session_state.get("live_monitor")
        transfer_threshold = st.slider("Flag outbound flow above (MiB)", min_value=1, max_value=100, value=5, step=1, help="An alert is a review lead. Large transfers can be normal, so tune this threshold for your network.")
        if monitor and monitor.is_running:
            elapsed = max(0, int(datetime.now(timezone.utc).timestamp() - (monitor._started_at or datetime.now(timezone.utc).timestamp())))
            st.success(f"Monitoring is active · {monitor.interface} · {elapsed // 60} min {elapsed % 60} sec elapsed · auto-stops after {monitor.max_minutes} minutes")
            if st.button("Stop monitoring", type="secondary"):
                monitor.stop()
        else:
            if monitor and monitor.timed_out:
                st.warning("The previous capture reached its time limit and stopped.")
            if not interfaces:
                st.error("No capture interfaces were found. Confirm that Scapy and Npcap are installed.")
            else:
                labels = [label for label, _ in interfaces]
                interface_label = st.selectbox("Network interface", labels, help="Choose the active Wi-Fi or Ethernet adapter used by this computer.")
                selected_interface = dict(interfaces)[interface_label]
                max_minutes = st.select_slider("Auto-stop after", options=[1, 5, 10, 20, 30, 60], value=10, format_func=lambda value: f"{value} minute" if value == 1 else f"{value} minutes")
                if st.button("Start live monitoring", type="primary"):
                    try:
                        from live_capture import LiveFlowMonitor
                        new_monitor = LiveFlowMonitor(selected_interface, max_minutes=max_minutes)
                        new_monitor.start()
                        st.session_state["live_monitor"] = new_monitor
                        monitor = new_monitor
                    except Exception as exc:
                        st.error(str(exc))

        if monitor:
            refresh_interval = 2 if monitor.is_running else None

            @st.fragment(run_every=refresh_interval)
            def render_live_snapshot():
                snapshot = monitor.snapshot()
                if snapshot["error"]:
                    st.warning(snapshot["error"])
                flows = pd.DataFrame(snapshot["flows"])
                if flows.empty:
                    st.caption("Waiting for IP traffic on the selected interface…")
                    return
                reviewed = assess_live_flows(flows, transfer_threshold_mb=transfer_threshold)
                reviewed = score_live_anomalies(reviewed)
                model = st.session_state.get("supervised_model")
                model_features = st.session_state.get("supervised_features", [])
                if model is not None and model_features:
                    reviewed = score_live_with_trained_model(reviewed, model, model_features)
                flagged = reviewed[reviewed["alert"] == "Review"]
                metrics = st.columns(4)
                metrics[0].metric("Packets summarized", f"{snapshot['packet_total']:,}")
                metrics[1].metric("Active flows", f"{snapshot['flow_total']:,}")
                metrics[2].metric("Flows to review", f"{len(flagged):,}")
                metrics[3].metric("Capture", "Running" if snapshot["is_running"] else "Stopped")
                st.caption("A rolling Isolation Forest ranks outliers once 30 flows are available; explicit rules flag multi-port connections, large outbound flows, and short high-volume flows. These are review leads, not confirmed threats.")
                if model is not None:
                    st.caption("This session's trained classifier also scores current flows. Its predictions depend on the training data and label quality.")
                visible = [column for column in [
                    "start_time_utc", "direction", "internal_ip", "remote_ip", "remote_port",
                    "protocol", "packet_count", "total_bytes", "outbound_bytes",
                    "inbound_bytes", "duration_seconds", "risk_score", "anomaly_score", "alert",
                    "alert_reason", "model_prediction", "model_confidence",
                ] if column in reviewed]
                st.dataframe(reviewed.sort_values(["risk_score", "end_time"], ascending=[False, False])[visible].head(250), use_container_width=True, hide_index=True)
                st.download_button("Download flow summary CSV", reviewed.to_csv(index=False).encode("utf-8"), "live_flow_summary.csv", "text/csv")
                if len(flagged):
                    st.markdown("### Investigation suggestions")
                    st.markdown("- Check the flagged host and destination against your firewall, DNS, and endpoint logs.")
                    st.markdown("- Confirm whether the transfer or port activity matches an approved task before responding.")
                    st.markdown("- Treat model or rule alerts as candidates for review; this monitor does not confirm an incident.")
                else:
                    st.caption("No current flows crossed the review thresholds. This does not prove the computer is free of threats.")

            render_live_snapshot()

    elif section == "Train with labels":
        st.subheader("Train and evaluate a supervised model")
        st.write("Upload a flow-level CSV with a ground-truth label column. The app holds out a test split and reports standard classification metrics.")
        sample_dir = Path(__file__).resolve().parent
        st.download_button("Download labeled synthetic training CSV", (sample_dir / "demo_labeled_flows.csv").read_bytes(), "demo_labeled_flows.csv", "text/csv", help="Fabricated, labeled flow metadata for trying the supervised workflow.")
        st.caption("This synthetic dataset is for demonstrating the workflow only. Its evaluation scores are not evidence of real-world detection performance.")
        labeled = st.file_uploader("Upload labeled flow CSV", type=["csv"], key="labeled_csv", help="One row per flow. Include a label column such as label, class, or attack_type and numeric flow features.")
        if labeled:
            try:
                data = pd.read_csv(labeled)
                if len(data) < 10:
                    st.error("Please provide at least 10 labeled rows for an initial evaluation.")
                    return
                likely = [c for c in data.columns if c.lower() in {"label", "class", "attack_type", "target"}]
                target = st.selectbox("Ground-truth label column", data.columns.tolist(), index=data.columns.get_loc(likely[0]) if likely else len(data.columns)-1)
                feature_cols = numeric_features(data, target=target)
                if len(feature_cols) < 2:
                    st.error("At least two numeric feature columns are needed, excluding the label.")
                    return
                y = data[target].astype(str).fillna("unknown")
                class_counts = y.value_counts()
                if len(class_counts) < 2:
                    st.error("The label column must contain at least two classes.")
                    return
                X = clean_for_model(data, feature_cols)
                X = X.loc[:, X.notna().any()]
                if X.shape[1] < 2:
                    st.error("Fewer than two usable numeric features remain.")
                    return
                if st.button("Train and evaluate Random Forest", type="primary"):
                    stratify = y if class_counts.min() >= 2 else None
                    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.25, random_state=42, stratify=stratify)
                    pipe = Pipeline([("imputer", SimpleImputer(strategy="median")),
                                     ("scale", StandardScaler()),
                                     ("model", RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1))])
                    pipe.fit(X_train, y_train)
                    pred = pipe.predict(X_test)
                    st.session_state["supervised_model"] = pipe
                    st.session_state["supervised_features"] = list(X.columns)
                    st.session_state["supervised_classes"] = list(pipe.classes_)
                    st.markdown("### Held-out evaluation")
                    m = st.columns(4)
                    m[0].metric("Accuracy", f"{accuracy_score(y_test, pred):.3f}")
                    m[1].metric("Macro precision", f"{precision_score(y_test, pred, average='macro', zero_division=0):.3f}")
                    m[2].metric("Macro recall", f"{recall_score(y_test, pred, average='macro', zero_division=0):.3f}")
                    m[3].metric("Macro F1", f"{f1_score(y_test, pred, average='macro', zero_division=0):.3f}")
                    report = classification_report(y_test, pred, output_dict=True, zero_division=0)
                    st.dataframe(pd.DataFrame(report).transpose().round(3), use_container_width=True)
                    labels = sorted(y.unique())
                    cm = pd.DataFrame(confusion_matrix(y_test, pred, labels=labels), index=labels, columns=labels)
                    st.caption("Confusion matrix · rows are actual labels, columns are predicted labels")
                    st.dataframe(cm, use_container_width=True)
                    importances = pd.Series(pipe.named_steps["model"].feature_importances_, index=X.columns).sort_values(ascending=False).head(12)
                    st.markdown("### Most influential features")
                    st.bar_chart(importances)
                    st.warning("A random split can overstate performance when flows from the same host, capture, or time period appear in both sets. For a research report, prefer a time-based or capture-based holdout and document the dataset and label quality.")
                    st.success("Model is available in this session. Use the scoring section below to upload a compatible CSV and get predictions.")
                st.caption(f"Loaded {len(data):,} rows · {len(class_counts)} classes · {len(feature_cols)} candidate numeric features.")
            except Exception as exc:
                st.error(f"Could not train on this file: {exc}")
        model = st.session_state.get("supervised_model")
        if model is not None:
            st.markdown("---")
            st.markdown("#### Score a new flow CSV with this trained model")
            score_file = st.file_uploader("Upload unlabeled flow CSV", type=["csv"], key="score_csv")
            if score_file:
                scored = pd.read_csv(score_file)
                cols = st.session_state["supervised_features"]
                sx = clean_for_model(scored, cols)
                predicted = model.predict(sx)
                scored["predicted_label"] = predicted
                if hasattr(model, "predict_proba"):
                    scored["model_confidence"] = model.predict_proba(sx).max(axis=1)
                st.dataframe(scored, use_container_width=True, hide_index=True)
                st.download_button("Download scored CSV", scored.to_csv(index=False).encode("utf-8"), "scored_flows.csv", "text/csv")
                st.markdown("### Recommendations")
                for tip in supervised_recommendations(scored):
                    st.markdown(f"- {tip}")

    else:
        st.subheader("Project overview")
        st.markdown("""
This local prototype studies detection of suspicious behavior in encrypted network traffic using **flow metadata**. It never decrypts a session.

**Two analysis modes**

- **Unlabeled PCAP / PCAPNG:** Scapy extracts bidirectional flow features; Isolation Forest flags unusual flows for review.
- **Live monitor:** Captures transient packet metadata on one local interface, aggregates it into flows in memory, and uses rolling Isolation Forest plus review rules to highlight possible scans or unusual outbound volume. A trained classifier from the current session can also score flows. It does not write packet payloads or PCAP files.
- **Labeled flow CSV:** A Random Forest model trains on a held-out split and reports accuracy, macro precision, macro recall, macro F1, a confusion matrix, and feature importance.

**Research limits to document**

- Encrypted application contents are not visible; metadata cannot identify every threat.
- A plain PCAP has no ground-truth labels, so anomaly flags need human investigation.
- Results depend on dataset coverage, label quality, split strategy, and the chosen anomaly share.
- This prototype is for research and authorized offline analysis, not a production network defense system.
- Live capture on Windows requires Npcap and may require administrator privileges. Some adapters expose only partial traffic; loopback and VPN traffic may need a different interface.
""")
        st.markdown("#### Expected flow fields")
        st.code("duration_seconds, packet_count, total_bytes, forward_packets, reverse_packets, forward_bytes, reverse_bytes, mean_packet_size, std_packet_size, mean_interarrival_seconds, payload_bytes, syn_count, ack_count, rst_count, fin_count", language="text")


if __name__ == "__main__":
    main()

