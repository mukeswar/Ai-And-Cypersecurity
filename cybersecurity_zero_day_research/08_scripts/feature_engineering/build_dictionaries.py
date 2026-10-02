#!/usr/bin/env python3
"""Data dictionaries + explainability feature registry.

* CSE_CIC_IDS2018_dictionary.csv is built from the columns ACTUALLY present in
  the raw files (column_name_mapping.csv + raw_column_profile.csv) and the
  feature descriptions of the official CICFlowMeter ReadMe (saved under
  01_raw_data/CSE_CIC_IDS2018/_publisher_documentation/).
* CIC_IDS2017 / CIC_DDoS2019 / UNSW_NB15 dictionaries list the schema the
  publisher documents. They are flagged verified_against_raw=False until the
  raw files are placed in 01_raw_data and the pipeline is re-run.
* No feature engineering is performed: the unified schema only renames and
  converts units (see common.UNIFIED).
"""
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import DICT, OUT, READY, UNIFIED, snake  # noqa: E402

US = "microseconds"
# (CSE-CIC-IDS2018 name, CIC-IDS2017/DDoS2019 name, CICFlowMeter description, unit)
CIC = [
    ("Flow ID", "Flow ID", "Flow identifier (5-tuple + timestamp)", "id"),
    ("Src IP", "Source IP", "Source IP address", "id"),
    ("Src Port", "Source Port", "Source transport port", "port"),
    ("Dst IP", "Destination IP", "Destination IP address", "id"),
    ("Dst Port", "Destination Port", "Destination transport port", "port"),
    ("Protocol", "Protocol", "IP protocol number (6=TCP, 17=UDP, 0=other/unknown)", "IANA number"),
    ("Timestamp", "Timestamp", "Flow start time as recorded by the publisher", "datetime"),
    ("Flow Duration", "Flow Duration", "Duration of the flow in Microsecond", US),
    ("Tot Fwd Pkts", "Total Fwd Packets", "Total packets in the forward direction", "packets"),
    ("Tot Bwd Pkts", "Total Backward Packets", "Total packets in the backward direction", "packets"),
    ("TotLen Fwd Pkts", "Total Length of Fwd Packets", "Total size of packet in forward direction", "bytes"),
    ("TotLen Bwd Pkts", "Total Length of Bwd Packets", "Total size of packet in backward direction", "bytes"),
    ("Fwd Pkt Len Max", "Fwd Packet Length Max", "Maximum size of packet in forward direction", "bytes"),
    ("Fwd Pkt Len Min", "Fwd Packet Length Min", "Minimum size of packet in forward direction", "bytes"),
    ("Fwd Pkt Len Mean", "Fwd Packet Length Mean", "Mean size of packet in forward direction", "bytes"),
    ("Fwd Pkt Len Std", "Fwd Packet Length Std", "Standard deviation size of packet in forward direction", "bytes"),
    ("Bwd Pkt Len Max", "Bwd Packet Length Max", "Maximum size of packet in backward direction", "bytes"),
    ("Bwd Pkt Len Min", "Bwd Packet Length Min", "Minimum size of packet in backward direction", "bytes"),
    ("Bwd Pkt Len Mean", "Bwd Packet Length Mean", "Mean size of packet in backward direction", "bytes"),
    ("Bwd Pkt Len Std", "Bwd Packet Length Std", "Standard deviation size of packet in backward direction", "bytes"),
    ("Flow Byts/s", "Flow Bytes/s", "Number of flow bytes per second", "bytes/s"),
    ("Flow Pkts/s", "Flow Packets/s", "Number of flow packets per second", "packets/s"),
    ("Flow IAT Mean", "Flow IAT Mean", "Mean time between two packets sent in the flow", US),
    ("Flow IAT Std", "Flow IAT Std", "Standard deviation time between two packets sent in the flow", US),
    ("Flow IAT Max", "Flow IAT Max", "Maximum time between two packets sent in the flow", US),
    ("Flow IAT Min", "Flow IAT Min", "Minimum time between two packets sent in the flow", US),
    ("Fwd IAT Tot", "Fwd IAT Total", "Total time between two packets sent in the forward direction", US),
    ("Fwd IAT Mean", "Fwd IAT Mean", "Mean time between two packets sent in the forward direction", US),
    ("Fwd IAT Std", "Fwd IAT Std", "Standard deviation time between two packets sent in the forward direction", US),
    ("Fwd IAT Max", "Fwd IAT Max", "Maximum time between two packets sent in the forward direction", US),
    ("Fwd IAT Min", "Fwd IAT Min", "Minimum time between two packets sent in the forward direction", US),
    ("Bwd IAT Tot", "Bwd IAT Total", "Total time between two packets sent in the backward direction", US),
    ("Bwd IAT Mean", "Bwd IAT Mean", "Mean time between two packets sent in the backward direction", US),
    ("Bwd IAT Std", "Bwd IAT Std", "Standard deviation time between two packets sent in the backward direction", US),
    ("Bwd IAT Max", "Bwd IAT Max", "Maximum time between two packets sent in the backward direction", US),
    ("Bwd IAT Min", "Bwd IAT Min", "Minimum time between two packets sent in the backward direction", US),
    ("Fwd PSH Flags", "Fwd PSH Flags", "Times PSH flag set in forward packets (0 for UDP)", "count"),
    ("Bwd PSH Flags", "Bwd PSH Flags", "Times PSH flag set in backward packets (0 for UDP)", "count"),
    ("Fwd URG Flags", "Fwd URG Flags", "Times URG flag set in forward packets (0 for UDP)", "count"),
    ("Bwd URG Flags", "Bwd URG Flags", "Times URG flag set in backward packets (0 for UDP)", "count"),
    ("Fwd Header Len", "Fwd Header Length", "Total bytes used for headers in the forward direction", "bytes"),
    ("Bwd Header Len", "Bwd Header Length", "Total bytes used for headers in the backward direction", "bytes"),
    ("Fwd Pkts/s", "Fwd Packets/s", "Number of forward packets per second", "packets/s"),
    ("Bwd Pkts/s", "Bwd Packets/s", "Number of backward packets per second", "packets/s"),
    ("Pkt Len Min", "Min Packet Length", "Minimum length of a packet", "bytes"),
    ("Pkt Len Max", "Max Packet Length", "Maximum length of a packet", "bytes"),
    ("Pkt Len Mean", "Packet Length Mean", "Mean length of a packet", "bytes"),
    ("Pkt Len Std", "Packet Length Std", "Standard deviation length of a packet", "bytes"),
    ("Pkt Len Var", "Packet Length Variance", "Variance length of a packet", "bytes^2"),
    ("FIN Flag Cnt", "FIN Flag Count", "Number of packets with FIN", "packets"),
    ("SYN Flag Cnt", "SYN Flag Count", "Number of packets with SYN", "packets"),
    ("RST Flag Cnt", "RST Flag Count", "Number of packets with RST", "packets"),
    ("PSH Flag Cnt", "PSH Flag Count", "Number of packets with PUSH", "packets"),
    ("ACK Flag Cnt", "ACK Flag Count", "Number of packets with ACK", "packets"),
    ("URG Flag Cnt", "URG Flag Count", "Number of packets with URG", "packets"),
    ("CWE Flag Count", "CWE Flag Count", "Number of packets with CWR (publisher column spelled 'CWE')", "packets"),
    ("ECE Flag Cnt", "ECE Flag Count", "Number of packets with ECE", "packets"),
    ("Down/Up Ratio", "Down/Up Ratio", "Download and upload ratio", "ratio"),
    ("Pkt Size Avg", "Average Packet Size", "Average size of packet", "bytes"),
    ("Fwd Seg Size Avg", "Avg Fwd Segment Size", "Average size observed in the forward direction", "bytes"),
    ("Bwd Seg Size Avg", "Avg Bwd Segment Size", "Average size observed in the backward direction", "bytes"),
    ("Fwd Byts/b Avg", "Fwd Avg Bytes/Bulk", "Average number of bytes bulk rate in the forward direction", "bytes"),
    ("Fwd Pkts/b Avg", "Fwd Avg Packets/Bulk", "Average number of packets bulk rate in the forward direction", "packets"),
    ("Fwd Blk Rate Avg", "Fwd Avg Bulk Rate", "Average number of bulk rate in the forward direction", "rate"),
    ("Bwd Byts/b Avg", "Bwd Avg Bytes/Bulk", "Average number of bytes bulk rate in the backward direction", "bytes"),
    ("Bwd Pkts/b Avg", "Bwd Avg Packets/Bulk", "Average number of packets bulk rate in the backward direction", "packets"),
    ("Bwd Blk Rate Avg", "Bwd Avg Bulk Rate", "Average number of bulk rate in the backward direction", "rate"),
    ("Subflow Fwd Pkts", "Subflow Fwd Packets", "Average number of packets in a sub flow in the forward direction", "packets"),
    ("Subflow Fwd Byts", "Subflow Fwd Bytes", "Average number of bytes in a sub flow in the forward direction", "bytes"),
    ("Subflow Bwd Pkts", "Subflow Bwd Packets", "Average number of packets in a sub flow in the backward direction", "packets"),
    ("Subflow Bwd Byts", "Subflow Bwd Bytes", "Average number of bytes in a sub flow in the backward direction", "bytes"),
    ("Init Fwd Win Byts", "Init_Win_bytes_forward", "Bytes sent in initial window, forward (-1 = not available)", "bytes"),
    ("Init Bwd Win Byts", "Init_Win_bytes_backward", "Bytes sent in initial window, backward (-1 = not available)", "bytes"),
    ("Fwd Act Data Pkts", "act_data_pkt_fwd", "Packets with >=1 byte of TCP payload, forward", "packets"),
    ("Fwd Seg Size Min", "min_seg_size_forward", "Minimum segment size observed in the forward direction", "bytes"),
    ("Active Mean", "Active Mean", "Mean time a flow was active before becoming idle", US),
    ("Active Std", "Active Std", "Std. dev. time a flow was active before becoming idle", US),
    ("Active Max", "Active Max", "Maximum time a flow was active before becoming idle", US),
    ("Active Min", "Active Min", "Minimum time a flow was active before becoming idle", US),
    ("Idle Mean", "Idle Mean", "Mean time a flow was idle before becoming active", US),
    ("Idle Std", "Idle Std", "Std. dev. time a flow was idle before becoming active", US),
    ("Idle Max", "Idle Max", "Maximum time a flow was idle before becoming active", US),
    ("Idle Min", "Idle Min", "Minimum time a flow was idle before becoming active", US),
    ("Label", "Label", "Publisher class label (kept verbatim as original_label)", "category"),
]

# UNSW-NB15 partitioned training/testing set columns (publisher feature list, NUSW-NB15_features.csv)
UNSW = [
    ("id", "Record identifier", "id"), ("dur", "Record total duration", "seconds"),
    ("proto", "Transaction protocol", "category"), ("service", "Application service (http, ftp, dns, ... or '-')", "category"),
    ("state", "Protocol state (e.g. FIN, CON, INT)", "category"), ("spkts", "Source to destination packet count", "packets"),
    ("dpkts", "Destination to source packet count", "packets"), ("sbytes", "Source to destination transaction bytes", "bytes"),
    ("dbytes", "Destination to source transaction bytes", "bytes"), ("rate", "Packets per second (partitioned sets only)", "packets/s"),
    ("sttl", "Source to destination time to live", "hops"), ("dttl", "Destination to source time to live", "hops"),
    ("sload", "Source bits per second", "bits/s"), ("dload", "Destination bits per second", "bits/s"),
    ("sloss", "Source packets retransmitted or dropped", "packets"), ("dloss", "Destination packets retransmitted or dropped", "packets"),
    ("sinpkt", "Source interpacket arrival time", "milliseconds"), ("dinpkt", "Destination interpacket arrival time", "milliseconds"),
    ("sjit", "Source jitter", "milliseconds"), ("djit", "Destination jitter", "milliseconds"),
    ("swin", "Source TCP window advertisement", "bytes"), ("stcpb", "Source TCP base sequence number", "number"),
    ("dtcpb", "Destination TCP base sequence number", "number"), ("dwin", "Destination TCP window advertisement", "bytes"),
    ("tcprtt", "TCP connection setup round-trip time (synack + ackdat)", "seconds"),
    ("synack", "TCP setup time between SYN and SYN_ACK", "seconds"), ("ackdat", "TCP setup time between SYN_ACK and ACK", "seconds"),
    ("smean", "Mean of flow packet size transmitted by source", "bytes"), ("dmean", "Mean of flow packet size transmitted by destination", "bytes"),
    ("trans_depth", "Pipelined depth into the connection of HTTP request/response", "count"),
    ("response_body_len", "Size of data transferred from server's HTTP service", "bytes"),
    ("ct_srv_src", "Connections with same service and source address in last 100 connections", "count"),
    ("ct_state_ttl", "Number per state according to specific range of source/destination TTL", "count"),
    ("ct_dst_ltm", "Connections of same destination address in last 100 connections", "count"),
    ("ct_src_dport_ltm", "Connections of same source address and destination port in last 100 connections", "count"),
    ("ct_dst_sport_ltm", "Connections of same destination address and source port in last 100 connections", "count"),
    ("ct_dst_src_ltm", "Connections of same source and destination address in last 100 connections", "count"),
    ("is_ftp_login", "1 if FTP session accessed by user and password", "binary"),
    ("ct_ftp_cmd", "Number of flows with a command in FTP session", "count"),
    ("ct_flw_http_mthd", "Number of flows with methods such as GET and POST in HTTP service", "count"),
    ("ct_src_ltm", "Connections of same source address in last 100 connections", "count"),
    ("ct_srv_dst", "Connections with same service and destination address in last 100 connections", "count"),
    ("is_sm_ips_ports", "1 if source/destination IP and port are equal", "binary"),
    ("attack_cat", "Attack category name (kept verbatim as original_label)", "category"),
    ("label", "0 normal, 1 attack (publisher binary label)", "binary"),
]

# security interpretation for the explainability registry
SEC = {
    "protocol": "TCP vs UDP split separates e.g. UDP floods (LOIC-UDP) from TCP application attacks",
    "destination_port": "targeted service (21 FTP, 22 SSH, 80/443 web); strong but dataset-specific shortcut",
    "flow_duration": "very short flows -> scans/floods; very long -> slow DoS (Slowloris) or C2 sessions",
    "total_forward_packets": "request volume from initiator; high in brute force/floods",
    "total_backward_packets": "server response volume; near zero for unanswered floods/scans",
    "total_forward_bytes": "payload sent by initiator; large for uploads/exfiltration, tiny for SYN floods",
    "total_backward_bytes": "payload returned; large for downloads/data theft",
    "packet_rate": "packet intensity; flooding signature",
    "byte_rate": "bandwidth intensity; volumetric DDoS signature",
    "forward_packet_rate": "initiator sending intensity",
    "backward_packet_rate": "responder sending intensity",
    "forward_packet_length_mean": "typical request size; repeated identical sizes suggest automated tools",
    "backward_packet_length_mean": "typical response size; login failure pages give stable sizes in brute force",
    "packet_length_mean": "overall packet size profile",
    "packet_length_std": "regularity of packet sizes; low variance suggests scripted traffic",
    "packet_length_max": "largest packet; MTU-sized packets indicate bulk transfer",
    "inter_arrival_time_mean": "pacing of packets; slow DoS keeps long gaps, floods very short",
    "inter_arrival_time_std": "timing regularity; bots/beacons are periodic",
    "inter_arrival_time_max": "longest silence inside the flow",
    "forward_iat_mean": "pacing of initiator packets",
    "backward_iat_mean": "pacing of responder packets",
    "fin_flag_count": "graceful connection teardowns",
    "syn_flag_count": "connection attempts; SYN floods/scans",
    "rst_flag_count": "refused/aborted connections; scans hitting closed ports",
    "psh_flag_count": "interactive data pushes",
    "ack_flag_count": "established-session behaviour",
    "urg_flag_count": "rare urgent data; anomalous use can indicate evasion",
    "forward_init_window_bytes": "initial TCP window; fingerprint of OS/attack tool",
    "backward_init_window_bytes": "server initial TCP window",
    "down_up_ratio": "asymmetry of traffic; exfiltration vs download",
    "active_mean": "length of activity bursts",
    "idle_mean": "length of idle gaps; beaconing/C2 periodicity",
}


def main():
    os.makedirs(DICT, exist_ok=True)
    cm_path = os.path.join(DICT, "column_name_mapping.csv")
    prof_path = os.path.join(OUT, "tables", "raw_column_profile.csv")
    cm = pd.read_csv(cm_path) if os.path.exists(cm_path) else pd.DataFrame()
    prof = pd.read_csv(prof_path) if os.path.exists(prof_path) else pd.DataFrame()
    desc18 = {a: (d, u) for a, b, d, u in CIC}
    unified_of = {}
    for name, unit, d, m in UNIFIED:
        for ds, (raw, sc) in m.items():
            if raw:
                unified_of[(ds, raw)] = name

    # CSE-CIC-IDS2018: from actual raw columns
    rows = []
    sub = cm[cm.dataset == "CSE_CIC_IDS2018"] if len(cm) else cm
    if len(sub):
        files_total = sub.file_name.nunique()
        for raw, g in sub.groupby("raw_column", sort=False):
            p = prof[(prof.dataset == "CSE_CIC_IDS2018") & (prof.column == raw)] if len(prof) else prof
            d, u = desc18.get(raw.strip(), ("(no publisher description found)", ""))
            rows.append(dict(raw_column=raw, clean_column=snake(raw), description=d, unit=u,
                             present_in_files=f"{g.file_name.nunique()}/{files_total}",
                             cleaned_dtype="datetime64" if raw == "Timestamp" else ("string" if u in ("id", "category") else "float64"),
                             raw_missing=int(p.missing.sum()) if len(p) else "", raw_infinite=int(p.infinite.sum()) if len(p) else "",
                             raw_non_numeric=int(p.non_numeric.sum()) if len(p) else "",
                             unified_feature=unified_of.get(("CSE_CIC_IDS2018", raw.strip()), ""),
                             description_source="CICFlowMeter ReadMe (official GitHub)", verified_against_raw=True))
        pd.DataFrame(rows).to_csv(os.path.join(DICT, "CSE_CIC_IDS2018_dictionary.csv"), index=False)

    for ds in ["CIC_IDS2017", "CIC_DDoS2019"]:
        r = []
        for a, b, d, u in CIC:
            if ds == "CIC_IDS2017" and b in ("Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp"):
                note = "only in GeneratedLabelledFlows/TrafficLabelling CSVs"
            else:
                note = ""
            r.append(dict(raw_column=b, clean_column=snake(b), description=d, unit=u,
                          unified_feature=unified_of.get((ds, b), ""), notes=note,
                          description_source="CICFlowMeter ReadMe (official GitHub)",
                          verified_against_raw=False))
        extra = [("Fwd Header Length.1", "Duplicate of Fwd Header Length published by CIC", "bytes")] if ds == "CIC_IDS2017" else \
            [("Unnamed: 0", "Row index written by publisher", "id"), ("SimillarHTTP", "Publisher HTTP similarity field", "category"),
             ("Inbound", "Publisher inbound flag", "binary")]
        for c, d, u in extra:
            r.append(dict(raw_column=c, clean_column=snake(c), description=d, unit=u, unified_feature="",
                          notes="publisher-specific column", description_source="publisher files (expected)",
                          verified_against_raw=False))
        pd.DataFrame(r).to_csv(os.path.join(DICT, f"{ds}_dictionary.csv"), index=False)

    pd.DataFrame([dict(raw_column=c, clean_column=snake(c), description=d, unit=u,
                       unified_feature=unified_of.get(("UNSW_NB15", c), ""),
                       description_source="UNSW-NB15 publisher feature list (NUSW-NB15_features.csv)",
                       verified_against_raw=False) for c, d, u in UNSW]).to_csv(
        os.path.join(DICT, "UNSW_NB15_dictionary.csv"), index=False)

    # unified dictionary
    ur = []
    for name, unit, d, m in UNIFIED:
        row = dict(unified_feature=name, unit=unit, description=d)
        for ds, (raw, sc) in m.items():
            row[f"{ds}_source_column"] = raw or "NOT AVAILABLE (NaN)"
            row[f"{ds}_scale_factor"] = sc if raw else ""
        ur.append(row)
    meta = [("dataset_source", "", "Dataset identifier"), ("source_file", "", "Raw file name (provenance)"),
            ("row_in_file", "", "0-based data-row position in the raw file (provenance)"),
            ("timestamp", "datetime", "Publisher flow timestamp, parsed; as recorded (time zone not stated by publisher)"),
            ("original_label", "", "Publisher label, verbatim"), ("standardized_label", "", "Harmonised family (label_mapping_table.csv)"),
            ("mapping_confidence", "", "exact | publisher_category | ambiguous"), ("is_attack", "0/1", "standardized_label != BENIGN"),
            ("had_infinite_value", "bool", "row had +/-Infinity in any raw feature (set to NaN)"),
            ("model_feature_hash", "uint64", "hash of model-facing unified features (duplicate/leakage audits)")]
    for c, u, d in meta:
        ur.append(dict(unified_feature=c, unit=u, description=d))
    pd.DataFrame(ur).to_csv(os.path.join(DICT, "unified_dictionary.csv"), index=False)

    # explainability registry
    er = []
    model = set(pd.read_csv(os.path.join(READY, "model_feature_list.csv")).feature) \
        if os.path.exists(os.path.join(READY, "model_feature_list.csv")) else None
    for name, unit, d, m in UNIFIED:
        if model is not None and name not in model:
            continue
        srcs = "; ".join(f"{ds}:{raw}" for ds, (raw, sc) in m.items() if raw)
        er.append(dict(feature_name=name, feature_description=d, source_dataset=srcs, data_type="float64", unit=unit,
                       interpretation=f"Higher value = more {d.lower()}" if unit not in ("IANA number", "port") else "categorical code stored as number; treat as categorical in explanations",
                       potential_security_meaning=SEC.get(name, "")))
    pd.DataFrame(er).to_csv(os.path.join(DICT, "explainability_feature_registry.csv"), index=False)
    pd.DataFrame(er).to_csv(os.path.join(READY, "explainability_feature_registry.csv"), index=False)
    print("dictionaries written")


if __name__ == "__main__":
    main()
