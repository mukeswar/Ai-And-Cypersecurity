#!/usr/bin/env python3
"""Create CLEANED COPIES of raw files (raw files are opened read-only).

Steps per file (chunked, every step counted and logged to 09_logs/cleaning_log.csv):
  1. drop repeated in-file header rows (publisher artefact; not observations)
  2. drop completely empty rows (all fields blank)
  3. standardise column names (snake_case; raw->clean map in 03_data_dictionary)
  4. drop columns that are completely empty in the whole file
  5. parse timestamp -> `timestamp` (publisher format; unparsed -> NaT, counted)
  6. convert feature columns to numeric (non-numeric tokens -> NaN, counted)
  7. +/-Infinity -> NaN, with per-row flag `had_infinite_value` (counted per column)
  8. add provenance: dataset_source, source_file, row_in_file
  9. keep `original_label` untouched; add `standardized_label`, `mapping_confidence`, `is_attack`
 10. add `feature_hash` (uint64 over model-facing feature values) for duplicate/leakage audits
NOT done here (on purpose): imputation, duplicate removal, outlier clipping,
scaling. Missing values are reported, not filled: any imputation must be fit on
the training split only (see 06_analysis_ready/README.md).
"""
import os
import sys

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import (CHUNK_ROWS, CLEAN, DATASETS, DICT, IDENTIFIER_COLS, append_log, map_label, now,  # noqa: E402
                    plog, raw_files, rel, snake)

CLOG = ["timestamp_utc", "dataset", "file_name", "step", "column", "original_count", "method",
        "final_count", "rows_affected", "notes"]
INF = {"infinity", "-infinity", "+infinity", "inf", "-inf", "+inf"}
NON_FEATURE = {"label", "attack_cat", "timestamp", "flow_id", "src_ip", "dst_ip", "source_ip",
               "destination_ip", "srcip", "dstip", "proto", "service", "state"}


def clog(ds, fn, step, column="", original="", method="", final="", affected="", notes=""):
    append_log("cleaning_log.csv", dict(timestamp_utc=now(), dataset=ds, file_name=fn, step=step, column=column,
                                        original_count=original, method=method, final_count=final,
                                        rows_affected=affected, notes=notes), CLOG)


def empty_columns(path, enc):
    nonempty = None
    for ch in pd.read_csv(path, dtype=str, chunksize=CHUNK_ROWS, encoding=enc, keep_default_na=False):
        ne = (ch.apply(lambda s: s.str.strip()) != "").any()
        nonempty = ne if nonempty is None else (nonempty | ne)
    return [c for c, v in nonempty.items() if not v]


def clean_file(ds, path, colmap_rows):
    spec = DATASETS[ds]
    fn = os.path.basename(path)
    enc = spec["encoding"]
    try:
        open(path, encoding="utf-8").read(1 << 20)
        enc = "utf-8"
    except UnicodeDecodeError:
        pass
    out_dir = os.path.join(CLEAN, ds)
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, os.path.splitext(fn)[0] + ".parquet")
    empties = empty_columns(path, enc)
    for c in empties:
        clog(ds, fn, "drop_empty_column", c, "", "column entirely blank -> dropped", "", "")

    writer = None
    stats = dict(rows_in=0, header_rows=0, empty_rows=0, ts_unparsed=0, rows_out=0, rows_with_inf=0)
    inf_cnt, nonnum_cnt, miss_cnt, neg_cnt, nan_cnt = {}, {}, {}, {}, {}
    offset = 0
    schema = None
    for ch in pd.read_csv(path, dtype=str, chunksize=CHUNK_ROWS, encoding=enc, keep_default_na=False):
        raw_cols = list(ch.columns)
        ch.index = np.arange(offset, offset + len(ch))  # row_in_file: 0-based data row in raw file
        offset += len(ch)
        stats["rows_in"] += len(ch)
        hdr = (ch[raw_cols[0]] == raw_cols[0]) & (ch[raw_cols[-1]] == raw_cols[-1])
        stats["header_rows"] += int(hdr.sum())
        ch = ch[~hdr]
        blank = (ch.apply(lambda s: s.str.strip()) == "").all(axis=1)
        stats["empty_rows"] += int(blank.sum())
        ch = ch[~blank].drop(columns=empties)

        ren = {c: snake(c) for c in ch.columns}
        if not colmap_rows.get((ds, fn)):
            colmap_rows[(ds, fn)] = [(ds, fn, c, ren[c]) for c in ch.columns]
        ch = ch.rename(columns=ren)
        # CIC-IDS2017 publishes 'Fwd Header Length' twice; pandas suffixes .1 -> keep distinct name
        lab = snake(spec["label_col"])
        tcol = snake(spec["timestamp_col"]) if spec["timestamp_col"] else None

        out_df = pd.DataFrame(index=ch.index)
        out_df["dataset_source"] = ds
        out_df["source_file"] = fn
        out_df["row_in_file"] = ch.index.astype("int64")
        if tcol and tcol in ch:
            ts = pd.to_datetime(ch[tcol], format=spec["timestamp_format"], errors="coerce") \
                if spec["timestamp_format"] else pd.to_datetime(ch[tcol], errors="coerce")
            stats["ts_unparsed"] += int(ts.isna().sum())
            out_df["timestamp"] = ts
        else:
            out_df["timestamp"] = pd.NaT
        # identifiers kept as strings for provenance only
        for c in ch.columns:
            if c in IDENTIFIER_COLS - {"timestamp", tcol} or c in ("proto", "service", "state"):
                out_df[c] = ch[c].str.strip()
        any_inf = np.zeros(len(ch), bool)
        feat_cols = [c for c in ch.columns if c not in NON_FEATURE and c != tcol and c not in IDENTIFIER_COLS
                     and c != lab and c != "label"]
        for c in feat_cols:
            s = ch[c].str.strip()
            low = s.str.lower()
            isinf = low.isin(INF).to_numpy()
            blank_c = (s == "").to_numpy()
            num = pd.to_numeric(s.where(~isinf, None), errors="coerce")
            bad = num.isna().to_numpy() & ~isinf & ~blank_c & ~low.isin({"nan", "-nan"}).to_numpy()
            inf_cnt[c] = inf_cnt.get(c, 0) + int(isinf.sum())
            nonnum_cnt[c] = nonnum_cnt.get(c, 0) + int(bad.sum())
            miss_cnt[c] = miss_cnt.get(c, 0) + int(blank_c.sum())
            nan_cnt[c] = nan_cnt.get(c, 0) + int(low.isin({"nan", "-nan"}).sum())
            neg_cnt[c] = neg_cnt.get(c, 0) + int((num < 0).sum())
            any_inf |= isinf
            out_df[c] = num.astype("float64")
        stats["rows_with_inf"] += int(any_inf.sum())
        out_df["had_infinite_value"] = any_inf
        orig = ch[lab].astype(str) if lab in ch else pd.Series("", index=ch.index)
        out_df["original_label"] = orig.values
        mapped = orig.map(lambda v: map_label(ds, v))
        out_df["standardized_label"] = [m[0] for m in mapped]
        out_df["mapping_confidence"] = [m[1] for m in mapped]
        out_df["is_attack"] = (out_df["standardized_label"] != "BENIGN").astype("int8")
        if ds == "UNSW_NB15" and "label" in ch:
            out_df["publisher_binary_label"] = pd.to_numeric(ch["label"], errors="coerce").astype("Int8")
        hcols = sorted(feat_cols)
        out_df["feature_hash"] = pd.util.hash_pandas_object(out_df[hcols], index=False).to_numpy()
        out_df = out_df.reset_index(drop=True)
        tbl = pa.Table.from_pandas(out_df, preserve_index=False)
        if writer is None:
            schema = tbl.schema
            writer = pq.ParquetWriter(out, schema, compression="zstd")
        else:
            tbl = tbl.cast(schema)
        writer.write_table(tbl)
        stats["rows_out"] += len(out_df)
    writer.close()

    clog(ds, fn, "drop_repeated_header_rows", "", stats["header_rows"], "rows equal to header -> dropped (not observations)",
         0, stats["header_rows"])
    clog(ds, fn, "drop_completely_empty_rows", "", stats["empty_rows"], "all fields blank -> dropped", 0, stats["empty_rows"])
    clog(ds, fn, "parse_timestamp", spec["timestamp_col"] or "", stats["ts_unparsed"],
         f"pd.to_datetime(format={spec['timestamp_format']}) ; unparsed -> NaT (rows kept)", stats["ts_unparsed"], "")
    for c in inf_cnt:
        if inf_cnt[c]:
            clog(ds, fn, "infinite_to_nan", c, inf_cnt[c], "+/-Infinity -> NaN; row flag had_infinite_value=True",
                 inf_cnt[c] + miss_cnt[c], inf_cnt[c])
        if nan_cnt[c]:
            clog(ds, fn, "literal_nan_reported", c, nan_cnt[c], "publisher wrote 'NaN' (e.g. 0/0 rate) -> NaN; no imputation",
                 nan_cnt[c], 0)
        if nonnum_cnt[c]:
            clog(ds, fn, "non_numeric_to_nan", c, nonnum_cnt[c], "pd.to_numeric(errors='coerce')", nonnum_cnt[c], nonnum_cnt[c])
        if miss_cnt[c]:
            clog(ds, fn, "missing_values_reported", c, miss_cnt[c], "no imputation (to be fit on train split only)",
                 miss_cnt[c] + inf_cnt[c] + nonnum_cnt[c], 0)
        if neg_cnt[c]:
            clog(ds, fn, "negative_values_reported", c, neg_cnt[c],
                 "kept as published (e.g. CICFlowMeter uses -1 for unavailable init window)", neg_cnt[c], 0)
    clog(ds, fn, "summary", "", stats["rows_in"], "rows_in -> rows_out", stats["rows_out"],
         stats["rows_in"] - stats["rows_out"], f"rows_with_inf={stats['rows_with_inf']} out={rel(out)}")
    plog("clean_dataset.py", "clean", ds, rel(path), rel(out), stats["rows_in"], stats["rows_out"],
         f"header_rows={stats['header_rows']} empty_rows={stats['empty_rows']} rows_with_inf={stats['rows_with_inf']}")
    return stats


def main(only=None):
    colmap = {}
    for ds in DATASETS:
        if only and ds not in only:
            continue
        for p in raw_files(ds):
            print("cleaning", rel(p), flush=True)
            clean_file(ds, p, colmap)
    rows = [r for v in colmap.values() for r in v]
    if rows:
        cm = pd.DataFrame(rows, columns=["dataset", "file_name", "raw_column", "clean_column"])
        path = os.path.join(DICT, "column_name_mapping.csv")
        if os.path.exists(path) and only:
            old = pd.read_csv(path)
            cm = pd.concat([old[~old.dataset.isin(only)], cm])
        cm.to_csv(path, index=False)


if __name__ == "__main__":
    main(sys.argv[1:] or None)
