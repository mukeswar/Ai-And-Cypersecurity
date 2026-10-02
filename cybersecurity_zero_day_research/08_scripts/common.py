"""Shared configuration for the data pipeline.

Everything that encodes a methodological decision (dataset specs, label
mapping, unified feature schema, split definitions) lives here so that it is
reviewed in one place and versioned with the code.
"""
import csv
import datetime as dt
import glob
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RAW = os.path.join(ROOT, "01_raw_data")
META = os.path.join(ROOT, "02_raw_metadata")
DICT = os.path.join(ROOT, "03_data_dictionary")
CLEAN = os.path.join(ROOT, "04_cleaned_data")
HARM = os.path.join(ROOT, "05_harmonized_data")
READY = os.path.join(ROOT, "06_analysis_ready")
LOGS = os.path.join(ROOT, "09_logs")
OUT = os.path.join(ROOT, "10_research_outputs")

RANDOM_SEED = 20260930  # only used for documented sampling of preview CSVs
CHUNK_ROWS = 500_000

# --------------------------------------------------------------------------
# Dataset specifications. Column names are the RAW names as published.
# --------------------------------------------------------------------------
DATASETS = {
    "CSE_CIC_IDS2018": {
        "name": "CSE-CIC-IDS2018 (Processed Traffic Data for ML Algorithms)",
        "pattern": "*_TrafficForML_CICFlowMeter.csv",
        "label_col": "Label",
        "timestamp_col": "Timestamp",
        "timestamp_format": "%d/%m/%Y %H:%M:%S",
        "header": "infer",
        "encoding": "utf-8",
        # Published hours only span 01..12 (12-hour clock, AM/PM dropped). Verified against the
        # publisher's attack schedule (e.g. SSH-Bruteforce 14:01-15:31 appears as hours 2-3).
        "twelve_hour_clock_fix": True,
    },
    "CIC_IDS2017": {
        "name": "CIC-IDS2017",
        # MachineLearningCVE/*.csv (no timestamp) or TrafficLabelling/*.csv (with timestamp)
        "pattern": "**/*.pcap_ISCX.csv",
        "label_col": "Label",
        "timestamp_col": "Timestamp",
        # Publisher files use e.g. 3/7/2017 8:55 (month first, 12h clock without AM/PM on
        # some days). Parsed leniently; see methodology_notes.md (known limitation).
        "timestamp_format": None,
        "header": "infer",
        "encoding": "latin-1",  # 'Web Attack \x96 Brute Force' uses a cp1252 dash
    },
    "CIC_DDoS2019": {
        "name": "CIC-DDoS2019",
        "pattern": "**/*.csv",
        "label_col": "Label",
        "timestamp_col": "Timestamp",
        "timestamp_format": None,  # e.g. 2018-12-01 10:51:39.813448
        "header": "infer",
        "encoding": "utf-8",
    },
    "UNSW_NB15": {
        "name": "UNSW-NB15",
        # Official partitioned train/test sets. The four full CSVs (UNSW-NB15_1..4.csv)
        # have no header and are handled by the adapter when present.
        "pattern": "**/UNSW_NB15_*ing-set.csv",
        "label_col": "attack_cat",
        "timestamp_col": None,  # train/test sets carry no timestamp; stime/ltime only in full CSVs
        "timestamp_format": None,
        "header": "infer",
        "encoding": "utf-8",
    },
}


def capture_day(fname):
    """Capture day (ISO) from publisher file names such as Wednesday-14-02-2018_... (dd-mm-yyyy)."""
    m = re.search(r"(\d{2})-(\d{2})-(\d{4})", os.path.basename(fname))
    return f"{m.group(3)}-{m.group(2)}-{m.group(1)}" if m else None


# Hours (as published, 12-hour clock) that belong to the afternoon of a capture day. The CIC
# testbed day runs ~08:00-18:00, so published 01..05 = 13..17 h. 06 and 07 cannot be resolved
# (could be morning or evening) and are left unshifted but flagged.
PM_HOURS = range(1, 6)
AMBIGUOUS_HOURS = (6, 7)


def correct_timestamp(ts, day):
    """Return (corrected_timestamp, correction_flag) for a 12-hour-clock series.

    flags: none | pm_shift_+12h | ambiguous_hour_kept | invalid_date_set_NaT
    """
    import pandas as pd
    flag = pd.Series("none", index=ts.index, dtype=object)
    out = ts.copy()
    bad = ts.isna() | (ts.dt.strftime("%Y-%m-%d") != day)
    h = ts.dt.hour
    pm = ~bad & h.isin(list(PM_HOURS))
    amb = ~bad & h.isin(AMBIGUOUS_HOURS)
    out[pm] = ts[pm] + pd.Timedelta(hours=12)
    out[bad] = pd.NaT
    flag[pm] = "pm_shift_+12h"
    flag[amb] = "ambiguous_hour_kept"
    flag[bad] = "invalid_date_set_NaT"
    return out, flag


def raw_files(ds):
    spec = DATASETS[ds]
    files = glob.glob(os.path.join(RAW, ds, spec["pattern"]), recursive=True)
    return sorted(f for f in files if "_publisher_documentation" not in f)


def snake(name):
    """Standardise a column name: strip, lowercase, non-alphanumerics -> '_'."""
    s = name.strip().replace("/", "_per_")
    s = re.sub(r"[^0-9A-Za-z]+", "_", s).strip("_").lower()
    return s


# --------------------------------------------------------------------------
# Label harmonisation. original_label is never modified; this table produces
# standardized_label. mapping_confidence: exact | publisher_category | ambiguous
# Ambiguous labels are NOT forced into a family: they get UNMAPPED_AMBIGUOUS.
# --------------------------------------------------------------------------
LABEL_MAP = [
    # dataset, original_label (case-insensitive, whitespace-normalised), standardized, confidence, rationale
    ("*", "benign", "BENIGN", "exact", "benign traffic"),
    ("UNSW_NB15", "normal", "BENIGN", "exact", "UNSW-NB15 uses 'Normal' for benign traffic"),
    # CSE-CIC-IDS2018
    ("CSE_CIC_IDS2018", "dos attacks-goldeneye", "DOS", "exact", "DoS variant"),
    ("CSE_CIC_IDS2018", "dos attacks-slowloris", "DOS", "exact", "DoS variant"),
    ("CSE_CIC_IDS2018", "dos attacks-slowhttptest", "DOS", "exact", "DoS variant"),
    ("CSE_CIC_IDS2018", "dos attacks-hulk", "DOS", "exact", "DoS variant"),
    ("CSE_CIC_IDS2018", "ddos attacks-loic-http", "DDOS", "exact", "DDoS variant"),
    ("CSE_CIC_IDS2018", "ddos attack-loic-udp", "DDOS", "exact", "DDoS variant"),
    ("CSE_CIC_IDS2018", "ddos attack-hoic", "DDOS", "exact", "DDoS variant"),
    ("CSE_CIC_IDS2018", "ftp-bruteforce", "BRUTE_FORCE", "exact", "FTP credential brute force"),
    ("CSE_CIC_IDS2018", "ssh-bruteforce", "BRUTE_FORCE", "exact", "SSH credential brute force"),
    ("CSE_CIC_IDS2018", "brute force -web", "WEB_ATTACK", "publisher_category",
     "publisher lists it under the 'Web attacks' scenario (DVWA login brute force)"),
    ("CSE_CIC_IDS2018", "brute force -xss", "WEB_ATTACK", "publisher_category", "publisher 'Web attacks' scenario (XSS)"),
    ("CSE_CIC_IDS2018", "sql injection", "WEB_ATTACK", "publisher_category", "publisher 'Web attacks' scenario"),
    ("CSE_CIC_IDS2018", "infilteration", "INFILTRATION", "exact", "publisher spelling 'Infilteration' kept in original_label"),
    ("CSE_CIC_IDS2018", "bot", "BOT", "exact", "Ares botnet scenario"),
    # CIC-IDS2017
    ("CIC_IDS2017", "dos hulk", "DOS", "exact", "DoS variant"),
    ("CIC_IDS2017", "dos goldeneye", "DOS", "exact", "DoS variant"),
    ("CIC_IDS2017", "dos slowloris", "DOS", "exact", "DoS variant"),
    ("CIC_IDS2017", "dos slowhttptest", "DOS", "exact", "DoS variant"),
    ("CIC_IDS2017", "ddos", "DDOS", "exact", "LOIC DDoS"),
    ("CIC_IDS2017", "portscan", "PORT_SCAN", "exact", "port scan"),
    ("CIC_IDS2017", "ftp-patator", "BRUTE_FORCE", "exact", "FTP brute force (Patator)"),
    ("CIC_IDS2017", "ssh-patator", "BRUTE_FORCE", "exact", "SSH brute force (Patator)"),
    ("CIC_IDS2017", "web attack - brute force", "WEB_ATTACK", "publisher_category", "publisher 'Web Attack' family"),
    ("CIC_IDS2017", "web attack - xss", "WEB_ATTACK", "publisher_category", "publisher 'Web Attack' family"),
    ("CIC_IDS2017", "web attack - sql injection", "WEB_ATTACK", "publisher_category", "publisher 'Web Attack' family"),
    ("CIC_IDS2017", "infiltration", "INFILTRATION", "exact", "infiltration"),
    ("CIC_IDS2017", "bot", "BOT", "exact", "Ares botnet"),
    ("CIC_IDS2017", "heartbleed", "OTHER", "exact", "vulnerability exploit; no dedicated family in taxonomy"),
    # CIC-DDoS2019 (all reflection/exploitation DDoS per publisher)
    *[("CIC_DDoS2019", l, "DDOS", "publisher_category", "publisher classifies as reflection/exploitation DDoS")
      for l in ["drdos_dns", "drdos_ldap", "drdos_mssql", "drdos_netbios", "drdos_ntp", "drdos_snmp",
                "drdos_ssdp", "drdos_udp", "syn", "tftp", "udp-lag", "udplag", "webddos", "portmap",
                "ldap", "mssql", "netbios", "udp"]],
    # UNSW-NB15 attack_cat
    ("UNSW_NB15", "dos", "DOS", "exact", "DoS"),
    ("UNSW_NB15", "backdoor", "OTHER", "exact", "documented attack without taxonomy family"),
    ("UNSW_NB15", "backdoors", "OTHER", "exact", "documented attack without taxonomy family"),
    ("UNSW_NB15", "exploits", "OTHER", "exact", "documented attack without taxonomy family"),
    ("UNSW_NB15", "shellcode", "OTHER", "exact", "documented attack without taxonomy family"),
    ("UNSW_NB15", "worms", "OTHER", "exact", "self-propagating malware; not a botnet per publisher"),
    ("UNSW_NB15", "analysis", "UNMAPPED_AMBIGUOUS", "ambiguous",
     "publisher groups port scan, spam and HTML-file penetration: mixed families"),
    ("UNSW_NB15", "reconnaissance", "UNMAPPED_AMBIGUOUS", "ambiguous",
     "includes but is not limited to port scanning; not forced into PORT_SCAN"),
    ("UNSW_NB15", "fuzzers", "UNMAPPED_AMBIGUOUS", "ambiguous", "fuzzing can be DoS-like or probing"),
    ("UNSW_NB15", "generic", "UNMAPPED_AMBIGUOUS", "ambiguous", "technique against block ciphers; no family match"),
]

_LM = {}
for ds, orig, std, conf, why in LABEL_MAP:
    _LM[(ds, orig)] = (std, conf, why)


def norm_label(s):
    s = str(s).replace("\x96", "-").replace("–", "-").replace("�", "-")
    return re.sub(r"\s+", " ", s).strip().lower()


def map_label(ds, original):
    """Return (standardized_label, mapping_confidence). Unknown labels -> UNMAPPED_UNKNOWN."""
    k = norm_label(original)
    if k in ("", "nan", "none"):
        return "MISSING_LABEL", "missing"
    hit = _LM.get((ds, k)) or _LM.get(("*", k))
    if hit:
        return hit[0], hit[1]
    return "UNMAPPED_UNKNOWN", "unknown"


# --------------------------------------------------------------------------
# Unified (harmonised) network feature schema.
# Each entry: unified_name -> {dataset: raw column name or None}, unit, transform.
# None means the dataset does not provide the feature -> NaN (never fabricated).
# Unit conversions are the only transforms applied (documented per row).
# --------------------------------------------------------------------------
CIC18 = "CSE_CIC_IDS2018"
CIC17 = "CIC_IDS2017"
DD19 = "CIC_DDoS2019"
UNSW = "UNSW_NB15"

# (unified, unit, description, {ds: (raw_col, scale)})
_US = 1e-6  # CICFlowMeter time features are microseconds -> seconds
UNIFIED = [
    ("protocol", "IANA number", "Transport protocol number",
     {CIC18: ("Protocol", 1), CIC17: ("Protocol", 1), DD19: ("Protocol", 1), UNSW: (None, 1)}),
    ("source_port", "port", "Source transport port",
     {CIC18: ("Src Port", 1), CIC17: ("Source Port", 1), DD19: ("Source Port", 1), UNSW: (None, 1)}),
    ("destination_port", "port", "Destination transport port",
     {CIC18: ("Dst Port", 1), CIC17: ("Destination Port", 1), DD19: ("Destination Port", 1), UNSW: (None, 1)}),
    ("flow_duration", "seconds", "Flow duration",
     {CIC18: ("Flow Duration", _US), CIC17: ("Flow Duration", _US), DD19: ("Flow Duration", _US), UNSW: ("dur", 1)}),
    ("total_forward_packets", "packets", "Packets source->destination",
     {CIC18: ("Tot Fwd Pkts", 1), CIC17: ("Total Fwd Packets", 1), DD19: ("Total Fwd Packets", 1), UNSW: ("spkts", 1)}),
    ("total_backward_packets", "packets", "Packets destination->source",
     {CIC18: ("Tot Bwd Pkts", 1), CIC17: ("Total Backward Packets", 1), DD19: ("Total Backward Packets", 1), UNSW: ("dpkts", 1)}),
    ("total_forward_bytes", "bytes", "Bytes source->destination (CIC: payload length; UNSW: transaction bytes)",
     {CIC18: ("TotLen Fwd Pkts", 1), CIC17: ("Total Length of Fwd Packets", 1), DD19: ("Total Length of Fwd Packets", 1), UNSW: ("sbytes", 1)}),
    ("total_backward_bytes", "bytes", "Bytes destination->source (CIC: payload length; UNSW: transaction bytes)",
     {CIC18: ("TotLen Bwd Pkts", 1), CIC17: ("Total Length of Bwd Packets", 1), DD19: ("Total Length of Bwd Packets", 1), UNSW: ("dbytes", 1)}),
    ("packet_rate", "packets/s", "Flow packets per second (as published)",
     {CIC18: ("Flow Pkts/s", 1), CIC17: ("Flow Packets/s", 1), DD19: ("Flow Packets/s", 1), UNSW: ("rate", 1)}),
    ("byte_rate", "bytes/s", "Flow bytes per second (as published)",
     {CIC18: ("Flow Byts/s", 1), CIC17: ("Flow Bytes/s", 1), DD19: ("Flow Bytes/s", 1), UNSW: (None, 1)}),
    ("forward_packet_rate", "packets/s", "Forward packets per second",
     {CIC18: ("Fwd Pkts/s", 1), CIC17: ("Fwd Packets/s", 1), DD19: ("Fwd Packets/s", 1), UNSW: (None, 1)}),
    ("backward_packet_rate", "packets/s", "Backward packets per second",
     {CIC18: ("Bwd Pkts/s", 1), CIC17: ("Bwd Packets/s", 1), DD19: ("Bwd Packets/s", 1), UNSW: (None, 1)}),
    ("forward_packet_length_mean", "bytes", "Mean forward packet size",
     {CIC18: ("Fwd Pkt Len Mean", 1), CIC17: ("Fwd Packet Length Mean", 1), DD19: ("Fwd Packet Length Mean", 1), UNSW: ("smean", 1)}),
    ("backward_packet_length_mean", "bytes", "Mean backward packet size",
     {CIC18: ("Bwd Pkt Len Mean", 1), CIC17: ("Bwd Packet Length Mean", 1), DD19: ("Bwd Packet Length Mean", 1), UNSW: ("dmean", 1)}),
    ("packet_length_mean", "bytes", "Mean packet length over the flow",
     {CIC18: ("Pkt Len Mean", 1), CIC17: ("Packet Length Mean", 1), DD19: ("Packet Length Mean", 1), UNSW: (None, 1)}),
    ("packet_length_std", "bytes", "Std. dev. of packet length",
     {CIC18: ("Pkt Len Std", 1), CIC17: ("Packet Length Std", 1), DD19: ("Packet Length Std", 1), UNSW: (None, 1)}),
    ("packet_length_max", "bytes", "Max packet length",
     {CIC18: ("Pkt Len Max", 1), CIC17: ("Max Packet Length", 1), DD19: ("Max Packet Length", 1), UNSW: (None, 1)}),
    ("inter_arrival_time_mean", "seconds", "Mean inter-arrival time of packets in the flow",
     {CIC18: ("Flow IAT Mean", _US), CIC17: ("Flow IAT Mean", _US), DD19: ("Flow IAT Mean", _US), UNSW: (None, 1)}),
    ("inter_arrival_time_std", "seconds", "Std. dev. of inter-arrival time",
     {CIC18: ("Flow IAT Std", _US), CIC17: ("Flow IAT Std", _US), DD19: ("Flow IAT Std", _US), UNSW: (None, 1)}),
    ("inter_arrival_time_max", "seconds", "Max inter-arrival time",
     {CIC18: ("Flow IAT Max", _US), CIC17: ("Flow IAT Max", _US), DD19: ("Flow IAT Max", _US), UNSW: (None, 1)}),
    ("forward_iat_mean", "seconds", "Mean forward inter-arrival time (UNSW: sintpkt, ms->s)",
     {CIC18: ("Fwd IAT Mean", _US), CIC17: ("Fwd IAT Mean", _US), DD19: ("Fwd IAT Mean", _US), UNSW: ("sinpkt", 1e-3)}),
    ("backward_iat_mean", "seconds", "Mean backward inter-arrival time (UNSW: dintpkt, ms->s)",
     {CIC18: ("Bwd IAT Mean", _US), CIC17: ("Bwd IAT Mean", _US), DD19: ("Bwd IAT Mean", _US), UNSW: ("dinpkt", 1e-3)}),
    ("fin_flag_count", "packets", "Packets with TCP FIN",
     {CIC18: ("FIN Flag Cnt", 1), CIC17: ("FIN Flag Count", 1), DD19: ("FIN Flag Count", 1), UNSW: (None, 1)}),
    ("syn_flag_count", "packets", "Packets with TCP SYN",
     {CIC18: ("SYN Flag Cnt", 1), CIC17: ("SYN Flag Count", 1), DD19: ("SYN Flag Count", 1), UNSW: (None, 1)}),
    ("rst_flag_count", "packets", "Packets with TCP RST",
     {CIC18: ("RST Flag Cnt", 1), CIC17: ("RST Flag Count", 1), DD19: ("RST Flag Count", 1), UNSW: (None, 1)}),
    ("psh_flag_count", "packets", "Packets with TCP PSH",
     {CIC18: ("PSH Flag Cnt", 1), CIC17: ("PSH Flag Count", 1), DD19: ("PSH Flag Count", 1), UNSW: (None, 1)}),
    ("ack_flag_count", "packets", "Packets with TCP ACK",
     {CIC18: ("ACK Flag Cnt", 1), CIC17: ("ACK Flag Count", 1), DD19: ("ACK Flag Count", 1), UNSW: (None, 1)}),
    ("urg_flag_count", "packets", "Packets with TCP URG",
     {CIC18: ("URG Flag Cnt", 1), CIC17: ("URG Flag Count", 1), DD19: ("URG Flag Count", 1), UNSW: (None, 1)}),
    ("forward_init_window_bytes", "bytes", "Initial TCP window, forward (UNSW: swin)",
     {CIC18: ("Init Fwd Win Byts", 1), CIC17: ("Init_Win_bytes_forward", 1), DD19: ("Init_Win_bytes_forward", 1), UNSW: ("swin", 1)}),
    ("backward_init_window_bytes", "bytes", "Initial TCP window, backward (UNSW: dwin)",
     {CIC18: ("Init Bwd Win Byts", 1), CIC17: ("Init_Win_bytes_backward", 1), DD19: ("Init_Win_bytes_backward", 1), UNSW: ("dwin", 1)}),
    ("down_up_ratio", "ratio", "Download/upload ratio",
     {CIC18: ("Down/Up Ratio", 1), CIC17: ("Down/Up Ratio", 1), DD19: ("Down/Up Ratio", 1), UNSW: (None, 1)}),
    ("active_mean", "seconds", "Mean time flow was active before idle",
     {CIC18: ("Active Mean", _US), CIC17: ("Active Mean", _US), DD19: ("Active Mean", _US), UNSW: (None, 1)}),
    ("idle_mean", "seconds", "Mean time flow was idle before active",
     {CIC18: ("Idle Mean", _US), CIC17: ("Idle Mean", _US), DD19: ("Idle Mean", _US), UNSW: (None, 1)}),
]
UNIFIED_FEATURES = [u[0] for u in UNIFIED]

META_COLS = ["dataset_source", "source_file", "row_in_file", "timestamp",
             "original_label", "standardized_label", "mapping_confidence", "is_attack"]

# Columns that identify hosts/flows. Kept in cleaned data for provenance but
# excluded from every model-facing feature set (dataset-specific identifiers).
IDENTIFIER_COLS = {"flow_id", "src_ip", "dst_ip", "source_ip", "destination_ip", "srcip", "dstip",
                   "timestamp", "stime", "ltime", "id"}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def append_log(name, row, fields):
    path = os.path.join(LOGS, name)
    os.makedirs(LOGS, exist_ok=True)
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in fields})


PROC_FIELDS = ["timestamp_utc", "script", "step", "dataset", "input", "output", "rows_in", "rows_out", "details"]


def plog(script, step, dataset="", input="", output="", rows_in="", rows_out="", details=""):
    append_log("processing_log.csv", dict(timestamp_utc=now(), script=script, step=step, dataset=dataset,
                                          input=input, output=output, rows_in=rows_in, rows_out=rows_out,
                                          details=details), PROC_FIELDS)


def rel(p):
    return os.path.relpath(p, ROOT)
