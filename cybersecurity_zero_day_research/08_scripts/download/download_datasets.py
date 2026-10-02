#!/usr/bin/env python3
"""Download public intrusion-detection datasets from their OFFICIAL publishers only.

Raw files are written once into 01_raw_data/<DATASET>/ and are never modified
afterwards. Existing files with a matching size are skipped (idempotent).
Every attempt (success, skip, failure) is appended to 09_logs/download_log.csv.

Access rules followed:
  * no authentication bypass, no scraping behind registration forms,
  * no unofficial mirrors when an official source exists.

Datasets whose official distribution requires a web registration form or a
SharePoint/OneDrive link (CIC-IDS2017, CIC-DDoS2019, UNSW-NB15, TON_IoT) are
listed in MANUAL_SOURCES: the researcher downloads them by hand from the
official page and places the files in the indicated folder. The rest of the
pipeline picks them up automatically.

Usage:
    python 08_scripts/download/download_datasets.py            # all automatic sources
    python 08_scripts/download/download_datasets.py --list     # show sources only
"""
import argparse
import csv
import datetime as dt
import os
import re
import sys
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW = os.path.join(ROOT, "01_raw_data")
LOG = os.path.join(ROOT, "09_logs", "download_log.csv")

# CSE-CIC-IDS2018 is officially distributed through the AWS Open Data Registry
# (https://registry.opendata.aws/cse-cic-ids2018/), bucket s3://cse-cic-ids2018,
# region ca-central-1, no sign-in required.
S3_BUCKET = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com"
S3_PREFIX = "Processed Traffic Data for ML Algorithms/"

MANUAL_SOURCES = {
    "CIC_IDS2017": {
        "official_page": "https://www.unb.ca/cic/datasets/ids-2017.html",
        "files": "MachineLearningCSV.zip (MachineLearningCVE/*.csv, 8 daily CSVs) "
                 "and optionally GeneratedLabelledFlows.zip (TrafficLabelling/*.csv, includes Flow ID/IPs/Timestamp)",
    },
    "CIC_DDoS2019": {
        "official_page": "https://www.unb.ca/cic/datasets/ddos-2019.html",
        "files": "CSV-01-12.zip and CSV-03-11.zip (CICFlowMeter CSVs per attack)",
    },
    "UNSW_NB15": {
        "official_page": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "files": "UNSW_NB15_training-set.csv, UNSW_NB15_testing-set.csv, UNSW-NB15_1..4.csv, "
                 "NUSW-NB15_features.csv, UNSW-NB15_LIST_EVENTS.csv",
    },
    "TON_IoT": {
        "official_page": "https://research.unsw.edu.au/projects/toniot-datasets",
        "files": "Train_Test_datasets/Train_Test_Network_dataset/train_test_network.csv (optional)",
    },
}


def log(row):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    new = not os.path.exists(LOG)
    with open(LOG, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp_utc", "dataset", "file_name", "url", "bytes", "status", "message"])
        if new:
            w.writeheader()
        w.writerow(row)


def list_s3(prefix):
    keys, token = [], None
    while True:
        q = {"list-type": "2", "prefix": prefix}
        if token:
            q["continuation-token"] = token
        with urllib.request.urlopen(f"{S3_BUCKET}/?{urllib.parse.urlencode(q)}", timeout=60) as r:
            xml = r.read().decode()
        for k, s in re.findall(r"<Key>(.*?)</Key>.*?<Size>(\d+)</Size>", xml, re.S):
            if not k.endswith("/"):
                keys.append((k, int(s)))
        m = re.search(r"<NextContinuationToken>(.*?)</NextContinuationToken>", xml)
        if not m:
            return keys
        token = m.group(1)


def fetch(url, dest, expected):
    if os.path.exists(dest) and os.path.getsize(dest) == expected:
        return "skipped_exists"
    if os.path.exists(dest):
        # A partial file from an interrupted run is not "raw data" yet; restart it.
        os.remove(dest)
    tmp = dest + ".part"
    last = None
    for attempt in range(4):  # retry transient network truncation
        try:
            with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 22)
                    if not chunk:
                        break
                    f.write(chunk)
            if os.path.getsize(tmp) != expected:
                raise IOError(f"size mismatch {os.path.getsize(tmp)} != {expected}")
            break
        except Exception as e:
            last = e
            if os.path.exists(tmp):
                os.remove(tmp)
    else:
        raise last
    os.rename(tmp, dest)
    os.chmod(dest, 0o444)  # raw files are read-only
    return "downloaded"


def download_cse_cic_ids2018():
    out = os.path.join(RAW, "CSE_CIC_IDS2018")
    os.makedirs(out, exist_ok=True)
    for key, size in list_s3(S3_PREFIX):
        name = os.path.basename(key)
        url = f"{S3_BUCKET}/{urllib.parse.quote(key)}"
        now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        try:
            status = fetch(url, os.path.join(out, name), size)
            log(dict(timestamp_utc=now, dataset="CSE_CIC_IDS2018", file_name=name, url=url,
                     bytes=size, status=status, message="official AWS Open Data bucket"))
            print(status, name, size, flush=True)
        except Exception as e:  # keep going, record the failure
            log(dict(timestamp_utc=now, dataset="CSE_CIC_IDS2018", file_name=name, url=url,
                     bytes=size, status="failed", message=str(e)[:300]))
            print("FAILED", name, e, file=sys.stderr, flush=True)


def report_manual():
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    for ds, info in MANUAL_SOURCES.items():
        folder = os.path.join(RAW, ds)
        present = [f for f in os.listdir(folder)] if os.path.isdir(folder) else []
        present = [f for f in present if not f.startswith(".") and f != "PLACE_FILES_HERE.md"]
        status = "present_manual" if present else "pending_manual_download"
        log(dict(timestamp_utc=now, dataset=ds, file_name=";".join(present)[:300], url=info["official_page"],
                 bytes="", status=status, message=info["files"]))
        print(f"{ds}: {status} -> {info['official_page']}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for k, s in list_s3(S3_PREFIX):
            print(s, k)
        for ds, info in MANUAL_SOURCES.items():
            print(ds, info["official_page"])
        sys.exit(0)
    download_cse_cic_ids2018()
    report_manual()
