#!/usr/bin/env python3
"""Build analysis-ready splits from the harmonised data (no shuffling, no scaling).

Primary dataset: CSE-CIC-IDS2018 (the only dataset whose raw files are present).
The same code runs for any dataset in common.DATASETS whose capture days are
defined in CAPTURE_DAYS.

1. STANDARD split (closed-world benchmark)
   Within every (capture_day, original_label) group, flows are ordered by
   (timestamp, row_in_file) and cut chronologically: first 70% -> train,
   next 15% -> validation, last 15% -> test. Every split therefore contains
   every class, and no later flow of an attack episode is used to train on an
   earlier one.
2. CROSS-SPLIT DUPLICATE REMOVAL (leakage control)
   Validation/test rows whose model-facing feature vector (model_feature_hash)
   also occurs in the corresponding training set are removed from val/test and
   counted. Training rows are never removed. Within-split duplicates are kept
   and reported.
3. ZERO-DAY-LIKE (unseen-attack simulation) scenarios
   One attack family is withheld from train and validation entirely; all of its
   rows are placed in test (flag is_unseen_family=1). These are SIMULATED
   unseen attacks, not genuine zero-day attacks.
4. CONTINUAL-LEARNING stages: consecutive blocks of capture days (strictly
   chronological). Stage val/test rows are de-duplicated against the cumulative
   training data of stages <= current stage.

No statistic is computed on validation/test data for preprocessing; train-only
descriptive statistics are written for later scaling/imputation.
"""
import glob
import json
import os
import sys

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import (HARM, IDENTIFIER_COLS, OUT, READY, RANDOM_SEED, UNIFIED_FEATURES, plog)  # noqa: E402

DS = "CSE_CIC_IDS2018"
TRAIN_FRAC, VAL_FRAC = 0.70, 0.15
# source_port is an ephemeral, per-connection identifier and published for one day only -> not a model feature
MODEL_FEATURES = [f for f in UNIFIED_FEATURES if f != "source_port"]

ZERO_DAY = {
    "zero_day_scenario_01": ["WEB_ATTACK"],
    "zero_day_scenario_02": ["INFILTRATION"],
    "zero_day_scenario_03": ["BOT"],
}
STAGES = {  # capture days (ISO) per stage, chronological, non-overlapping
    1: ["2018-02-14", "2018-02-15"],
    2: ["2018-02-16", "2018-02-20"],
    3: ["2018-02-21", "2018-02-22", "2018-02-23"],
    4: ["2018-02-28", "2018-03-01"],
    5: ["2018-03-02"],
}
STAGE_ROLE = {1: "initial traffic distribution", 2: "new attack distribution (new DoS variants + DDoS)",
              3: "evolving traffic (new DDoS variant) + new family WEB_ATTACK",
              4: "new attack family INFILTRATION", 5: "final unseen-attack evaluation (BOT never seen before)"}


DROP_COLS = ["date", "year", "month", "day", "hour"]  # recomputable from timestamp


def load_day(path):
    df = pd.read_parquet(path)  # carries capture_day, corrected timestamp, labels, unified features
    return df.drop(columns=[c for c in DROP_COLS if c in df])


def assign_split(df):
    df = df.sort_values(["timestamp", "row_in_file"], kind="stable", na_position="last")
    split = np.empty(len(df), dtype=object)
    for _, idx in df.groupby(["capture_day", "original_label"], sort=False).indices.items():
        n = len(idx)
        a = int(np.floor(n * TRAIN_FRAC))
        b = int(np.floor(n * (TRAIN_FRAC + VAL_FRAC)))
        s = np.array(["train"] * a + ["validation"] * (b - a) + ["test"] * (n - b), dtype=object)
        split[idx] = s  # idx are positions in the time-sorted frame -> chronological cut
    df["split"] = split
    nat = df["timestamp"].isna()
    df.loc[nat, "split"] = "excluded_no_timestamp"
    return df


class Sink:
    """Append DataFrames to a parquet file with a fixed schema."""

    def __init__(self, path):
        self.path, self.w, self.schema, self.n = path, None, None, 0
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, df):
        if df.empty:
            return
        t = pa.Table.from_pandas(df, preserve_index=False)
        if self.w is None:
            self.schema = t.schema
            self.w = pq.ParquetWriter(self.path, self.schema, compression="zstd")
        else:
            t = t.cast(self.schema)
        self.w.write_table(t)
        self.n += len(df)

    def close(self):
        if self.w:
            self.w.close()


def sample_csv(parquet_path, per_class=2000):
    """Documented preview: the first `per_class` rows per standardized_label in stored order
    (capture-day files in name order, time-sorted within each day). Deterministic, no random draw.
    Streams row groups so the 11M-row training file is never fully loaded."""
    if not os.path.exists(parquet_path):
        return
    pf = pq.ParquetFile(parquet_path)
    classes = set(pf.read(columns=["standardized_label"]).column(0).to_pandas().astype(str).unique())
    got, parts = {c: 0 for c in classes}, []
    for i in range(pf.num_row_groups):
        if all(v >= per_class for v in got.values()):
            break
        df = pf.read_row_group(i).to_pandas()
        lab = df.standardized_label.astype(str)
        for c in classes:
            need = per_class - got[c]
            if need > 0:
                take = df[lab == c].head(need)
                got[c] += len(take)
                parts.append(take)
    pd.concat(parts).to_csv(parquet_path.replace(".parquet", "_sample.csv"), index=False)


def train_stats(parquet_path, out_csv):
    df = pd.read_parquet(parquet_path, columns=MODEL_FEATURES)
    d = df.describe(percentiles=[0.25, 0.5, 0.75]).T
    d["missing"] = df.isna().sum()
    d["n_unique"] = df.nunique()
    d.index.name = "feature"
    d.to_csv(out_csv)


def main():
    # temporal_data files hold keys + corrected time + labels + unified features (one per capture day)
    files = sorted(glob.glob(os.path.join(HARM, "temporal_data", DS, "*.parquet")))
    if not files:
        sys.exit("no harmonised files; run harmonize.py first")

    # ---------- pass 1: assign splits, collect hashes
    parts, meta = {}, []
    for p in files:
        df = assign_split(load_day(p))
        parts[p] = df[["source_file", "row_in_file", "split"]].astype({"split": "category"})
        m = df[["capture_day", "original_label", "standardized_label", "split", "model_feature_hash", "timestamp"]].copy()
        for c in ["capture_day", "original_label", "standardized_label", "split"]:
            m[c] = m[c].astype(str)
        meta.append(m)
        print("split", os.path.basename(p), df.split.value_counts().to_dict(), flush=True)
    M = pd.concat(meta, ignore_index=True)
    for c in ["capture_day", "original_label", "standardized_label", "split"]:
        M[c] = M[c].astype("category")
    del meta
    train_h = np.unique(M.loc[M.split == "train", "model_feature_hash"].to_numpy())
    val_h = np.unique(M.loc[M.split == "validation", "model_feature_hash"].to_numpy())

    # conflicting labels: same model-facing vector, >1 standardized label
    conf = M.groupby("model_feature_hash", observed=True)["standardized_label"].nunique()
    conflicting_vectors = int((conf > 1).sum())
    conflicting_rows = int(M["model_feature_hash"].isin(conf[conf > 1].index).sum())
    within_dups = {s: int(M[M.split == s].duplicated("model_feature_hash").sum()) for s in ["train", "validation", "test"]}

    # ---------- pass 2: write standard split + zero-day + CL
    sinks = {s: Sink(os.path.join(READY, d, f"network_harmonized_{n}.parquet"))
             for s, d, n in [("train", "train", "train"), ("validation", "validation", "validation"), ("test", "test", "test")]}
    full = Sink(os.path.join(READY, "network_harmonized.parquet"))
    zsinks = {z: {s: Sink(os.path.join(READY, "zero_day", z, f"{s}.parquet")) for s in ["train", "validation", "test"]}
              for z in ZERO_DAY}
    zero_train_h = {}
    for z, fam in ZERO_DAY.items():
        zero_train_h[z] = np.unique(M.loc[(M.split == "train") & ~M.standardized_label.isin(fam), "model_feature_hash"])
    zero_val_h = {z: np.unique(M.loc[(M.split == "validation") & ~M.standardized_label.isin(f), "model_feature_hash"])
                  for z, f in ZERO_DAY.items()}
    removed = {"validation": 0, "test": 0}
    zremoved = {z: {"validation": 0, "test": 0} for z in ZERO_DAY}
    stage_of_day = {d: s for s, ds in STAGES.items() for d in ds}
    csinks = {s: Sink(os.path.join(READY, "continual_learning", f"continual_learning_stage_{s}.parquet")) for s in STAGES}
    cum_train = {s: np.unique(M.loc[(M.split == "train") & M.capture_day.map(stage_of_day).le(s),
                                    "model_feature_hash"]) for s in STAGES}
    cremoved = {s: 0 for s in STAGES}
    temporal_violations = []
    for p in files:
        df = load_day(p).merge(parts[p], on=["source_file", "row_in_file"], validate="1:1")
        df = df.sort_values(["timestamp", "row_in_file"], kind="stable")
        df["removed_reason"] = ""
        v = df.split == "validation"
        t = df.split == "test"
        dv = v & df.model_feature_hash.isin(train_h)
        dt_ = t & (df.model_feature_hash.isin(train_h) | df.model_feature_hash.isin(val_h))
        df.loc[dv, "removed_reason"] = "duplicate_of_train_vector"
        df.loc[dt_, "removed_reason"] = "duplicate_of_train_or_validation_vector"
        removed["validation"] += int(dv.sum())
        removed["test"] += int(dt_.sum())
        # temporal ordering check per (day,label)
        for (d, l), g in df[df.split != "excluded_no_timestamp"].groupby(["capture_day", "original_label"]):
            tr, va, te = (g.loc[g.split == s, "timestamp"] for s in ["train", "validation", "test"])
            if len(tr) and len(va) and tr.max() > va.min():
                temporal_violations.append((d, l, "train>val"))
            if len(va) and len(te) and va.max() > te.min():
                temporal_violations.append((d, l, "val>test"))
        full.write(df)
        keep = df.removed_reason == ""
        for s in ["train", "validation", "test"]:
            sinks[s].write(df[keep & (df.split == s)])
        # zero-day (no full-frame copies: write masked subsets)
        base_cols = [c for c in df.columns if c != "removed_reason"]
        for z, fam in ZERO_DAY.items():
            unseen = df.standardized_label.isin(fam).to_numpy()
            zs = np.where(unseen, "test", df.split.to_numpy())
            h = df.model_feature_hash
            zv = (zs == "validation") & h.isin(zero_train_h[z]).to_numpy()
            zt = (zs == "test") & (h.isin(zero_train_h[z]) | h.isin(zero_val_h[z])).to_numpy()
            zremoved[z]["validation"] += int(zv.sum())
            zremoved[z]["test"] += int(zt.sum())
            for s in ["train", "validation", "test"]:
                sel = (zs == s) & ~zv & ~zt
                zsinks[z][s].write(df.loc[sel, base_cols].assign(split=s, is_unseen_family=unseen[sel].astype("int8")))
        # continual learning
        st = stage_of_day[df.capture_day.iloc[0]]
        drop = ((df.split != "train") & df.model_feature_hash.isin(cum_train[st])).to_numpy()
        cremoved[st] += int(drop.sum())
        keep_cl = ~drop & (df.split != "excluded_no_timestamp").to_numpy()
        csinks[st].write(df.loc[keep_cl, base_cols].assign(stage=st))
        del df
    for s in list(sinks.values()) + [full] + [x for z in zsinks.values() for x in z.values()] + list(csinks.values()):
        s.close()

    # ---------- documentation of scenarios and stages
    summ = os.path.join(OUT, "summaries")
    os.makedirs(summ, exist_ok=True)
    zinfo = {}
    for z, fam in ZERO_DAY.items():
        cls = {}
        for s in ["train", "validation", "test"]:
            d = pd.read_parquet(os.path.join(READY, "zero_day", z, f"{s}.parquet"), columns=["standardized_label"])
            cls[s] = d.standardized_label.astype(str).value_counts().to_dict()  # str: no zero-count categories
        zinfo[z] = dict(withheld_families=fam, terminology="unseen-attack simulation (zero-day-like); NOT real zero-day attacks",
                        training_classes=sorted(cls["train"]), validation_classes=sorted(cls["validation"]),
                        testing_classes=sorted(cls["test"]), counts=cls,
                        removed_cross_split_duplicates=zremoved[z])
        with open(os.path.join(READY, "zero_day", z, "scenario.json"), "w") as f:
            json.dump(zinfo[z], f, indent=2)
    import shutil
    shutil.copyfile(os.path.join(READY, "zero_day", "zero_day_scenario_01", "test.parquet"),
                    os.path.join(READY, "zero_day", "zero_day_test.parquet"))

    cinfo, seen = {}, set()
    for s, days in STAGES.items():
        d = pd.read_parquet(os.path.join(READY, "continual_learning", f"continual_learning_stage_{s}.parquet"),
                            columns=["split", "standardized_label", "original_label", "timestamp"])
        d = d.astype({"split": str, "standardized_label": str, "original_label": str})
        fams = set(d.standardized_label.unique())
        variants = set(d.original_label.unique())
        per = {sp: d[d.split == sp] for sp in ["train", "validation", "test"]}
        cinfo[s] = dict(role=STAGE_ROLE[s], capture_days=days,
                        period={sp: [str(x.timestamp.min()), str(x.timestamp.max())] for sp, x in per.items()},
                        classes=sorted(fams), new_classes=sorted(fams - seen), previously_observed=sorted(fams & seen),
                        original_label_variants=sorted(variants),
                        samples={sp: int(len(x)) for sp, x in per.items()},
                        class_counts={sp: x.standardized_label.value_counts().to_dict() for sp, x in per.items()},
                        removed_val_test_duplicates_of_cumulative_train=cremoved[s])
        seen |= fams
    with open(os.path.join(READY, "continual_learning", "stages.json"), "w") as f:
        json.dump(cinfo, f, indent=2, default=str)

    # ---------- train-only statistics for later scaling / imputation
    train_stats(os.path.join(READY, "train", "network_harmonized_train.parquet"),
                os.path.join(READY, "train", "feature_stats_train_only.csv"))
    for z in ZERO_DAY:
        train_stats(os.path.join(READY, "zero_day", z, "train.parquet"),
                    os.path.join(READY, "zero_day", z, "feature_stats_train_only.csv"))
    pd.DataFrame(dict(feature=MODEL_FEATURES)).to_csv(os.path.join(READY, "model_feature_list.csv"), index=False)

    # ---------- class distribution
    std = {s: pd.read_parquet(os.path.join(READY, d, f"network_harmonized_{s}.parquet"),
                              columns=["original_label", "standardized_label"])
           for s, d in [("train", "train"), ("validation", "validation"), ("test", "test")]}
    allc = M.groupby(["standardized_label", "original_label"], observed=True).size().rename("number_of_samples")
    cd = allc.reset_index()
    cd.insert(0, "dataset", DS)
    cd["percentage"] = (100 * cd.number_of_samples / cd.number_of_samples.sum()).round(4)
    for s in ["train", "validation", "test"]:
        before = M[M.split == s].groupby(["standardized_label", "original_label"], observed=True).size()
        after = std[s].groupby(["standardized_label", "original_label"]).size()
        cd[f"{s}_count_before_dedup"] = cd.set_index(["standardized_label", "original_label"]).index.map(before).fillna(0).astype(int)
        cd[f"{s}_count"] = cd.set_index(["standardized_label", "original_label"]).index.map(after).fillna(0).astype(int)
    cd["imbalance_ratio_vs_majority"] = (cd.number_of_samples.max() / cd.number_of_samples).round(2)
    cd.to_csv(os.path.join(OUT, "tables", "class_distribution.csv"), index=False)
    cd.to_csv(os.path.join(READY, "class_distribution.csv"), index=False)

    # ---------- shortcut / label-leakage screen (descriptive, no model): per-feature value purity on TRAIN
    tr = pd.read_parquet(os.path.join(READY, "train", "network_harmonized_train.parquet"),
                         columns=MODEL_FEATURES + ["standardized_label"])
    purity = []
    for f in MODEL_FEATURES:
        x = tr[[f, "standardized_label"]]
        nun = x[f].nunique(dropna=True)
        if nun == 0:
            purity.append((f, 0, np.nan, "all missing"))
            continue
        ct = x.groupby([f, "standardized_label"], dropna=False).size()
        top = ct.groupby(level=0).max().sum() / len(x)  # accuracy of predicting majority label per exact value
        purity.append((f, nun, round(float(top), 4), ""))
    P = pd.DataFrame(purity, columns=["feature", "distinct_values_train", "value_to_label_purity", "note"])
    base = tr.standardized_label.value_counts(normalize=True).max()
    P["majority_class_baseline"] = round(float(base), 4)
    P.to_csv(os.path.join(OUT, "tables", "feature_label_purity_train.csv"), index=False)

    # ---------- leakage report
    rep = []
    rep.append("# Data Leakage Report\n")
    rep.append(f"Dataset: {DS}. Generated by `08_scripts/dataset_split/make_splits.py`. Split rule: within each "
               f"(capture_day, original_label) group, chronological {int(TRAIN_FRAC*100)}/{int(VAL_FRAC*100)}/"
               f"{int(round((1-TRAIN_FRAC-VAL_FRAC)*100))} cut by (timestamp, row_in_file). No shuffling.\n")
    rep.append("| # | Check | Result | Action |\n|---|---|---|---|")
    rep.append(f"| 1 | Duplicate samples across train/test (model-facing feature vector) | "
               f"{removed['test']:,} test rows duplicated a train/validation vector; {removed['validation']:,} validation rows duplicated a train vector | removed from val/test (training untouched); counts per class in class_distribution.csv |")
    rep.append(f"| 2 | Same flow in different splits (provenance key source_file+row_in_file) | each key assigned to exactly one split by construction (1:1 merge validated) | none needed |")
    rep.append(f"| 3 | Temporal leakage within (day,label) groups | {len(temporal_violations)} ordering violations | {'none' if not temporal_violations else 'see list below'} |")
    rep.append(f"| 3b | Temporal leakage across continual-learning stages | stages use disjoint, strictly increasing capture days {list(STAGES.values())} | none needed |")
    rep.append(f"| 3c | Standard split vs. future data | standard split is chronological *within* each day/label, not globally; days after a test flow can appear in train for other days | use continual_learning stages for strictly forward-in-time evaluation |")
    rep.append(f"| 4 | Label leakage | label columns (original_label, standardized_label, mapping_confidence, is_attack, is_unseen_family) are excluded from model_feature_list.csv | none needed |")
    rep.append(f"| 5 | Feature leakage / target-derived features | all model features are published CICFlowMeter flow statistics (unit conversion only); none computed from labels | none needed |")
    rep.append(f"| 6 | Dataset-specific identifiers | Flow ID, Src IP, Dst IP, Src Port, timestamp, source_file, row_in_file excluded from model features. destination_port IS a model feature and is a known shortcut risk in CIC datasets (attacks target fixed service ports) | report results with and without destination_port |")
    rep.append(f"| 7 | Preprocessing leakage / normalisation on test data | no scaling, imputation or clipping applied to any split; train-only statistics in feature_stats_train_only.csv | fit any scaler/imputer on train only |")
    rep.append(f"| 8 | Conflicting labels | {conflicting_vectors:,} feature vectors carry >1 standardized label ({conflicting_rows:,} rows) | kept; reported (irreducible error / label noise) |")
    rep.append(f"| 9 | Within-split exact duplicates | train {within_dups['train']:,}; validation {within_dups['validation']:,}; test {within_dups['test']:,} (before cross-split removal) | kept (not leakage); consider sample weighting |")
    rep.append(f"| 10 | Zero-day scenarios | withheld families absent from train/validation (asserted below) | see zero_day/*/scenario.json |")
    rep.append(f"| 11 | Single-feature shortcut screen | see 10_research_outputs/tables/feature_label_purity_train.csv (majority baseline {base:.4f}) | features with purity near 1.0 deserve scrutiny |")
    for z, info in zinfo.items():
        bad = set(info["training_classes"]) & set(info["withheld_families"])
        assert not bad, f"{z}: withheld family leaked into training"
        rep.append(f"\n- {z}: withheld {info['withheld_families']}; present in train/validation: {sorted(bad) or 'none'}; "
                   f"removed duplicates {info['removed_cross_split_duplicates']}")
    low = cd[(cd.test_count_before_dedup > 0) & (cd.test_count < 0.1 * cd.test_count_before_dedup)]
    if len(low):
        rep.append("\n**Warning - classes almost entirely removed from validation/test by de-duplication** "
                   "(their test flows are exact copies of training flows in the model-facing feature space; "
                   "a model can only 'memorise' them, so they cannot be evaluated meaningfully after de-duplication):\n")
        rep.append(low[["original_label", "test_count_before_dedup", "test_count", "validation_count_before_dedup",
                        "validation_count"]].to_markdown(index=False))
        rep.append("\nReport metrics both on the de-duplicated test set (primary) and, for comparability with prior work, "
                   "on the full test set (rows with removed_reason in network_harmonized.parquet).")
    if temporal_violations:
        rep.append("\nTemporal violations:\n" + "\n".join(f"- {a}" for a in temporal_violations[:50]))
    top = P.sort_values("value_to_label_purity", ascending=False).head(8)
    rep.append("\nTop single-feature value purity (train):\n\n" + top.to_markdown(index=False))
    txt = "\n".join(rep) + "\n"
    for path in [os.path.join(OUT, "summaries", "data_leakage_report.md"), os.path.join(READY, "data_leakage_report.md")]:
        with open(path, "w") as f:
            f.write(txt)

    for pth in [os.path.join(READY, "train", "network_harmonized_train.parquet"),
                os.path.join(READY, "validation", "network_harmonized_validation.parquet"),
                os.path.join(READY, "test", "network_harmonized_test.parquet"),
                os.path.join(READY, "zero_day", "zero_day_test.parquet")] + \
            [os.path.join(READY, "continual_learning", f"continual_learning_stage_{s}.parquet") for s in STAGES]:
        sample_csv(pth)
    plog("make_splits.py", "splits", DS, "05_harmonized_data", "06_analysis_ready", len(M), "",
         f"removed val={removed['validation']} test={removed['test']} conflicting_vectors={conflicting_vectors}")
    print("done")


if __name__ == "__main__":
    np.random.seed(RANDOM_SEED)
    main()
