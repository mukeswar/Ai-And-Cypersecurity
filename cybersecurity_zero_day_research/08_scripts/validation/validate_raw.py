#!/usr/bin/env python3
"""Validate every raw file WITHOUT modifying it.

Per file: existence, size, format, encoding (strict UTF-8 check), physical line
count, rows/columns parsed, malformed lines, repeated in-file header rows,
missing values per column, +/-Infinity and literal NaN strings, non-numeric
values in numeric columns, exact duplicate rows, label values, timestamp
availability/parse rate/range, SHA-256.

Outputs
  02_raw_metadata/raw_checksums.csv
  02_raw_metadata/data_validation_report.csv          (one row per file)
  10_research_outputs/tables/raw_column_profile.csv  (one row per file x column)
  10_research_outputs/tables/raw_label_counts.csv
"""
import codecs
import hashlib
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import (CHUNK_ROWS, DATASETS, META, OUT, plog, raw_files, rel)  # noqa: E402

INF_TOKENS = {"infinity", "-infinity", "+infinity", "inf", "-inf", "+inf"}
NAN_TOKENS = {"nan", "-nan"}
ID_COLS = {"Flow ID", "Src IP", "Dst IP", "Source IP", "Destination IP", "srcip", "dstip", "proto", "service", "state"}


def byte_pass(path, encoding):
    """SHA-256, line count and strict encoding check in one streaming pass."""
    h = hashlib.sha256()
    lines = 0
    dec = codecs.getincrementaldecoder("utf-8")("strict")
    utf8_ok = True
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 24)
            if not b:
                break
            h.update(b)
            lines += b.count(b"\n")
            if utf8_ok:
                try:
                    dec.decode(b)
                except UnicodeDecodeError:
                    utf8_ok = False
    return h.hexdigest(), lines, utf8_ok


def validate(ds, path):
    spec = DATASETS[ds]
    size = os.path.getsize(path)
    sha, lines, utf8_ok = byte_pass(path, spec["encoding"])
    enc = "utf-8" if utf8_ok else spec["encoding"]

    # Malformed lines are skipped by the parser and counted by comparing the
    # physical line count with parsed rows (reported as malformed_or_skipped_lines).
    reader = pd.read_csv(path, dtype=str, chunksize=CHUNK_ROWS, encoding=enc, keep_default_na=False,
                         on_bad_lines="skip", skipinitialspace=False)
    cols = None
    n = 0
    header_repeats = 0
    miss = inf = nan_lit = nonnum = None
    labels = {}
    hashes = []
    ts_ok = ts_bad = 0
    ts_min = ts_max = None
    lab = spec["label_col"]
    tcol = spec["timestamp_col"]
    for ch in reader:
        if cols is None:
            cols = list(ch.columns)
            k = len(cols)
            miss, inf, nan_lit, nonnum = (np.zeros(k, np.int64) for _ in range(4))
            stripped = [c.strip() for c in cols]
            lab_c = cols[stripped.index(lab)] if lab in stripped else None
            ts_c = cols[stripped.index(tcol)] if tcol and tcol in stripped else None
        # repeated header rows embedded in the data
        is_hdr = (ch[cols[0]] == cols[0]) & (ch[cols[-1]] == cols[-1])
        header_repeats += int(is_hdr.sum())
        ch = ch[~is_hdr]
        n += len(ch)
        hashes.append(pd.util.hash_pandas_object(ch, index=False).to_numpy())
        for j, c in enumerate(cols):
            v = ch[c]
            low = v.str.strip().str.lower()
            miss[j] += int((low == "").sum())
            inf[j] += int(low.isin(INF_TOKENS).sum())
            nan_lit[j] += int(low.isin(NAN_TOKENS).sum())
            if c not in (lab_c, ts_c) and c.strip() not in ID_COLS:
                num = pd.to_numeric(v, errors="coerce")
                nonnum[j] += int((num.isna() & (low != "") & ~low.isin(INF_TOKENS | NAN_TOKENS)).sum())
        if lab_c:
            for k_, c_ in ch[lab_c].value_counts().items():
                labels[k_] = labels.get(k_, 0) + int(c_)
        if ts_c:
            t = pd.to_datetime(ch[ts_c], format=spec["timestamp_format"], errors="coerce") \
                if spec["timestamp_format"] else pd.to_datetime(ch[ts_c], errors="coerce")
            ts_ok += int(t.notna().sum())
            ts_bad += int(t.isna().sum())
            if t.notna().any():
                a, b = t.min(), t.max()
                ts_min = a if ts_min is None or a < ts_min else ts_min
                ts_max = b if ts_max is None or b > ts_max else ts_max
    allh = np.concatenate(hashes) if hashes else np.array([], np.uint64)
    dup = int(len(allh) - len(np.unique(allh)))
    header_line = 1 if DATASETS[ds]["header"] == "infer" else 0
    malformed = lines - header_line - header_repeats - n  # skipped / blank lines
    summary = dict(
        dataset=ds, file_name=os.path.basename(path), relative_path=rel(path), exists=True,
        file_size_bytes=size, file_format=os.path.splitext(path)[1].lstrip(".").upper(),
        encoding_strict_utf8=utf8_ok, encoding_used=enc, physical_lines=lines,
        rows=n, columns=len(cols) if cols else 0,
        repeated_header_rows=header_repeats, malformed_or_skipped_lines=malformed,
        cells_missing_total=int(miss.sum()), columns_with_missing=int((miss > 0).sum()),
        cells_infinite_total=int(inf.sum()), columns_with_infinite=int((inf > 0).sum()),
        cells_literal_nan_total=int(nan_lit.sum()), cells_non_numeric_in_numeric_cols=int(nonnum.sum()),
        completely_empty_columns=int((miss == n).sum()) if n else 0,
        duplicate_rows_exact=dup, duplicate_pct=round(100 * dup / n, 4) if n else 0,
        label_column=lab, distinct_labels=len(labels), labels="; ".join(f"{k}={v}" for k, v in sorted(labels.items())),
        timestamp_column=tcol or "", timestamp_available=bool(tcol and ts_ok),
        timestamp_parsed=ts_ok, timestamp_unparsed=ts_bad,
        timestamp_min=str(ts_min) if ts_min is not None else "", timestamp_max=str(ts_max) if ts_max is not None else "",
        corrupted=bool(n == 0 or malformed < 0), sha256=sha,
    )
    prof = pd.DataFrame(dict(dataset=ds, file_name=os.path.basename(path), column=cols, missing=miss,
                             infinite=inf, literal_nan=nan_lit, non_numeric=nonnum,
                             missing_pct=np.round(100 * miss / max(n, 1), 4)))
    lc = pd.DataFrame([dict(dataset=ds, file_name=os.path.basename(path), original_label=k, count=v)
                       for k, v in sorted(labels.items())])
    return summary, prof, lc


def main():
    dl = os.path.join(os.path.dirname(META), "09_logs", "download_log.csv")
    dates = {}
    if os.path.exists(dl):
        d = pd.read_csv(dl)
        for _, r in d[d.status.isin(["downloaded", "skipped_exists"])].iterrows():
            dates.setdefault(r.file_name, str(r.timestamp_utc)[:10])
    rows, profs, lcs, sums = [], [], [], []
    for ds in DATASETS:
        files = raw_files(ds)
        if not files:
            rows.append(dict(dataset=ds, exists=False, file_name="", notes="no raw files present (pending manual download)"))
            continue
        for p in files:
            print("validating", rel(p), flush=True)
            s, pr, lc = validate(ds, p)
            rows.append(s)
            profs.append(pr)
            lcs.append(lc)
            sums.append(dict(file_name=s["file_name"], relative_path=s["relative_path"],
                             file_size=s["file_size_bytes"], SHA256=s["sha256"],
                             download_date=dates.get(s["file_name"], "manual/unknown")))
            plog("validate_raw.py", "validate", ds, rel(p), "", s["rows"], s["rows"],
                 f"dups={s['duplicate_rows_exact']} inf={s['cells_infinite_total']} hdr_repeats={s['repeated_header_rows']}")
    # publisher documentation files are raw too: checksum them
    for root, _, fs in os.walk(os.path.join(os.path.dirname(META), "01_raw_data")):
        for f in fs:
            p = os.path.join(root, f)
            if "_publisher_documentation" in p or "Nepal_public_data" in p:
                sums.append(dict(file_name=f, relative_path=rel(p), file_size=os.path.getsize(p),
                                 SHA256=byte_pass(p, "utf-8")[0], download_date=dates.get(f, "2026-10-02")))
    pd.DataFrame(rows).to_csv(os.path.join(META, "data_validation_report.csv"), index=False)
    pd.DataFrame(sums).to_csv(os.path.join(META, "raw_checksums.csv"), index=False)
    if profs:
        pd.concat(profs).to_csv(os.path.join(OUT, "tables", "raw_column_profile.csv"), index=False)
        pd.concat(lcs).to_csv(os.path.join(OUT, "tables", "raw_label_counts.csv"), index=False)
    print("done")


if __name__ == "__main__":
    main()
