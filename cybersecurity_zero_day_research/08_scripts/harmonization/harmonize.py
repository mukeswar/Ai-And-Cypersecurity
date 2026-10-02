#!/usr/bin/env python3
"""Map cleaned per-dataset files onto the unified schema (common.UNIFIED).

Rules
  * a unified feature is filled only from the documented raw column; if the
    dataset does not publish it the value is NaN (never derived/fabricated);
  * the only transformation is a documented unit conversion (scale factor,
    e.g. CICFlowMeter microseconds -> seconds);
  * original_label is carried through unchanged next to standardized_label;
  * row order inside each file is preserved; temporal tables are sorted by
    timestamp (stable sort, ties keep file order) and are NEVER shuffled.

Outputs
  05_harmonized_data/network_features/<DS>/<file>.parquet  keys + unified features
  05_harmonized_data/labels/<DS>_labels.parquet            keys + label columns
  05_harmonized_data/temporal_data/<DS>/<file>.parquet     time parts + labels + features, time-sorted
  05_harmonized_data/cross_dataset/feature_availability.csv
  05_harmonized_data/cross_dataset/label_mapping_applied.csv
  05_harmonized_data/labels/label_mapping_table.csv
"""
import glob
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import (CLEAN, DATASETS, HARM, LABEL_MAP, UNIFIED, UNIFIED_FEATURES, append_log, capture_day,
                    correct_timestamp, now, plog, rel, snake)  # noqa: E402

KEYS = ["dataset_source", "source_file", "row_in_file"]
LABELS = ["original_label", "standardized_label", "mapping_confidence", "is_attack"]


def harmonize_file(ds, path):
    import pyarrow.parquet as pq
    have = set(pq.read_schema(path).names)
    need = {snake(m.get(ds, (None, 1))[0]) for _, _, _, m in UNIFIED if m.get(ds, (None, 1))[0]}
    cols = [c for c in KEYS + ["timestamp", "had_infinite_value"] + LABELS if c in have] + sorted(need & have)
    df = pd.read_parquet(path, columns=cols)  # only what is needed (the 20-02 file has 7.9M rows)
    for c in ["dataset_source", "source_file", "original_label", "standardized_label", "mapping_confidence"]:
        df[c] = df[c].astype("category")
    out = df[KEYS].copy()
    day = capture_day(path)
    out["capture_day"] = day
    out["timestamp_as_published"] = df["timestamp"]
    if DATASETS[ds].get("twelve_hour_clock_fix"):
        ts, flag = correct_timestamp(df["timestamp"], day)
        vc = flag.value_counts()
        for k, n in vc.items():
            append_log("cleaning_log.csv", dict(timestamp_utc=now(), dataset=ds, file_name=os.path.basename(path),
                                                step="timestamp_12h_correction", column="timestamp",
                                                original_count=int(n), method=k, final_count=int(n), rows_affected=int(n) if k != "none" else 0,
                                                notes="published 12-hour clock without AM/PM; see methodology_notes.md"),
                       ["timestamp_utc", "dataset", "file_name", "step", "column", "original_count", "method",
                        "final_count", "rows_affected", "notes"])
    else:
        ts, flag = df["timestamp"], pd.Series("none", index=df.index)
    out["timestamp"] = ts
    out["timestamp_correction"] = pd.Categorical(flag.values)
    out["capture_day"] = out["capture_day"].astype("category")
    avail = {}
    for name, unit, desc, m in UNIFIED:
        raw, scale = m.get(ds, (None, 1))
        col = snake(raw) if raw else None
        if col and col in df:
            out[name] = df[col].astype("float64") * scale
            avail[name] = raw
        else:
            out[name] = np.nan
            avail[name] = None
    out["had_infinite_value"] = df["had_infinite_value"]
    out["model_feature_hash"] = pd.util.hash_pandas_object(
        out[UNIFIED_FEATURES].drop(columns=["source_port"]), index=False).to_numpy()
    for c in LABELS:
        out[c] = df[c]
    base = os.path.splitext(os.path.basename(path))[0]
    nf = os.path.join(HARM, "network_features", ds)
    os.makedirs(nf, exist_ok=True)
    out.drop(columns=LABELS).to_parquet(os.path.join(nf, base + ".parquet"), compression="zstd", index=False)

    t = out.sort_values("timestamp", kind="stable")
    ts = t["timestamp"]
    t.insert(6, "date", ts.dt.date.astype("string"))
    t.insert(7, "year", ts.dt.year.astype("Int16"))
    t.insert(8, "month", ts.dt.month.astype("Int8"))
    t.insert(9, "day", ts.dt.day.astype("Int8"))
    t.insert(10, "hour", ts.dt.hour.astype("Int8"))
    td = os.path.join(HARM, "temporal_data", ds)
    os.makedirs(td, exist_ok=True)
    t.to_parquet(os.path.join(td, base + ".parquet"), compression="zstd", index=False)
    return out[KEYS + LABELS + ["timestamp"]], avail, len(out)


def main():
    avail_rows, lab_tables = [], []
    for ds in DATASETS:
        files = sorted(glob.glob(os.path.join(CLEAN, ds, "*.parquet")))
        if not files:
            for name, unit, desc, m in UNIFIED:
                raw = m.get(ds, (None, 1))[0]
                avail_rows.append(dict(dataset=ds, unified_feature=name, raw_column=raw or "",
                                       available=bool(raw), status="dataset not yet downloaded"))
            continue
        labs, av = [], None
        for p in files:
            print("harmonizing", rel(p), flush=True)
            lab, av, n = harmonize_file(ds, p)
            labs.append(lab)
            plog("harmonize.py", "harmonize", ds, rel(p), "05_harmonized_data/", n, n, "unified schema")
        for name, unit, desc, m in UNIFIED:
            avail_rows.append(dict(dataset=ds, unified_feature=name, raw_column=av[name] or "",
                                   available=av[name] is not None,
                                   status="mapped" if av[name] else "NOT PUBLISHED by dataset -> NaN"))
        L = pd.concat(labs, ignore_index=True)
        os.makedirs(os.path.join(HARM, "labels"), exist_ok=True)
        L.to_parquet(os.path.join(HARM, "labels", f"{ds}_labels.parquet"), compression="zstd", index=False)
        g = L.groupby(["original_label", "standardized_label", "mapping_confidence"]).size().reset_index(name="rows")
        g.insert(0, "dataset", ds)
        lab_tables.append(g)
    os.makedirs(os.path.join(HARM, "cross_dataset"), exist_ok=True)
    pd.DataFrame(avail_rows).to_csv(os.path.join(HARM, "cross_dataset", "feature_availability.csv"), index=False)
    if lab_tables:
        pd.concat(lab_tables).to_csv(os.path.join(HARM, "cross_dataset", "label_mapping_applied.csv"), index=False)
    pd.DataFrame(LABEL_MAP, columns=["dataset", "original_label_normalised", "standardized_label",
                                     "mapping_confidence", "rationale"]).to_csv(
        os.path.join(HARM, "labels", "label_mapping_table.csv"), index=False)


if __name__ == "__main__":
    main()
