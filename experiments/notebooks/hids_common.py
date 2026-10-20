"""
hids_common.py - shared helpers for the Autoencoder HIDS notebooks
===================================================================
Place this file NEXT TO eda.ipynb and training.ipynb
(e.g. AUTOENCODER_HIDS/experiments/hids_common.py).

It is the single source of truth for:
  * the 22-feature definition (names + order exactly as in Report section 3.2)
  * the CIC-IDS2017 -> 22-feature derivation (with documented proxies)
  * the per-flow Scapy extractor (same 22 definitions, units = microseconds)
  * the scaler (log1p + Min-Max, bounded to [0, 1]), model, threshold, metrics
"""
import glob
import os
import re

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# 1. Feature definition (Report 3.2 / Appendix C)  - ORDER MATTERS
# --------------------------------------------------------------------------- #
FEATURE_GROUPS = {
    "Timing (6)":      ["flow_duration", "fwd_iat_mean", "fwd_iat_std",
                        "fwd_iat_min", "fwd_iat_max", "fwd_iat_total"],
    "Volume (5)":      ["fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_min",
                        "fwd_pkt_len_max", "total_fwd_bytes"],
    "Rate (2)":        ["flow_pkts_per_sec", "flow_bytes_per_sec"],
    "Burstiness (3)":  ["pkt_len_variance", "burst_ratio", "active_time_ratio"],
    "Session (3)":     ["pkt_count", "unique_ttl_count", "ttl_mean"],
    "Protocol flags (3)": ["tcp_flag_ratio", "has_udp", "has_tcp"],
}
FEATURE_NAMES = [f for grp in FEATURE_GROUPS.values() for f in grp]
assert len(FEATURE_NAMES) == 22 and len(set(FEATURE_NAMES)) == 22

# CICFlowMeter does not export every feature the live Scapy parser computes.
# These 7 are PROXIES when the source is the CIC-IDS2017 CSVs (be explicit about
# this in the report - see Limitations).
PROXY_FEATURES = {
    "burst_ratio":       "IAT coefficient of variation  CV/(1+CV)  (exact fraction-below-mean needs raw packets)",
    "active_time_ratio": "Active Mean / Flow Duration",
    "unique_ttl_count":  "min_seg_size_forward  (stack-fingerprint header field; CIC has no TTL)",
    "ttl_mean":          "Init_Win_bytes_forward (stack-fingerprint header field; CIC has no TTL)",
    "tcp_flag_ratio":    "(SYN+ACK flag count) / total packets",
    "has_tcp":           "Init_Win_bytes_forward >= 0 or any TCP flag count > 0",
    "has_udp":           "1 - has_tcp",
    "pkt_len_variance":  "Packet Length Variance (native, listed for completeness - NOT a proxy)",
}
PROXY_FEATURES.pop("pkt_len_variance")

ENCRYPTED_PORTS = {443, 8443, 993, 995, 465, 587}   # Report 1.6.1 (+8443)
MIN_PKTS = 5                                        # Report 3.2: parser needs >= 5 packets

RAW_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min",
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
    "Fwd IAT Max", "Fwd IAT Min", "Packet Length Variance", "SYN Flag Count",
    "ACK Flag Count", "FIN Flag Count", "RST Flag Count", "PSH Flag Count",
    "Active Mean", "Init_Win_bytes_forward", "min_seg_size_forward",
]


# --------------------------------------------------------------------------- #
# 2. CIC-IDS2017 loading  ->  22-feature matrix
# --------------------------------------------------------------------------- #
def normalise_label(s: pd.Series) -> pd.Series:
    """CIC labels contain a cp1252 en-dash that breaks naive string matching."""
    s = s.astype(str).str.replace("\x96", "-", regex=False).str.replace("\u2013", "-", regex=False)
    s = s.str.replace(r"[^\x20-\x7e]", "", regex=True).str.strip().str.upper()
    return s


def cic_to_22(raw: pd.DataFrame) -> pd.DataFrame:
    """Derive the 22 report features (report order) from CICFlowMeter columns."""
    r = raw.astype("float64")
    pos = lambda c: r[c].clip(lower=0)
    tot_pkts = r["Total Fwd Packets"] + r["Total Backward Packets"]
    cv = (r["Flow IAT Std"] / (r["Flow IAT Mean"].abs() + 1.0)).clip(lower=0)
    init_win = r["Init_Win_bytes_forward"]
    syn_ack = r["SYN Flag Count"] + r["ACK Flag Count"]
    any_flag = syn_ack + r["FIN Flag Count"] + r["RST Flag Count"] + r["PSH Flag Count"]
    has_tcp = ((init_win >= 0) | (any_flag > 0)).astype("float64")

    out = pd.DataFrame(index=raw.index)
    out["flow_duration"]      = pos("Flow Duration")
    out["fwd_iat_mean"]       = pos("Fwd IAT Mean")
    out["fwd_iat_std"]        = pos("Fwd IAT Std")
    out["fwd_iat_min"]        = pos("Fwd IAT Min")
    out["fwd_iat_max"]        = pos("Fwd IAT Max")
    out["fwd_iat_total"]      = pos("Fwd IAT Total")
    out["fwd_pkt_len_mean"]   = pos("Fwd Packet Length Mean")
    out["fwd_pkt_len_std"]    = pos("Fwd Packet Length Std")
    out["fwd_pkt_len_min"]    = pos("Fwd Packet Length Min")
    out["fwd_pkt_len_max"]    = pos("Fwd Packet Length Max")
    out["total_fwd_bytes"]    = pos("Total Length of Fwd Packets")
    out["flow_pkts_per_sec"]  = pos("Flow Packets/s")
    out["flow_bytes_per_sec"] = pos("Flow Bytes/s")
    out["pkt_len_variance"]   = pos("Packet Length Variance")
    out["burst_ratio"]        = cv / (1.0 + cv)
    out["active_time_ratio"]  = (pos("Active Mean") / (pos("Flow Duration") + 1.0)).clip(0, 1)
    out["pkt_count"]          = pos("Total Fwd Packets")
    out["unique_ttl_count"]   = pos("min_seg_size_forward")
    out["ttl_mean"]           = init_win.clip(lower=0)
    out["tcp_flag_ratio"]     = (syn_ack / tot_pkts.replace(0, np.nan)).clip(0, 1)
    out["has_udp"]            = 1.0 - has_tcp
    out["has_tcp"]            = has_tcp
    out = out[FEATURE_NAMES].copy()
    out["_tot_pkts"] = tot_pkts
    return out


def load_cic(dataset_dir, per_file_cap_benign=250_000, per_file_cap_malicious=100_000,
             min_pkts=MIN_PKTS, seed=42, verbose=True):
    """
    Reads every CIC-IDS2017 CSV ONE AT A TIME (RAM-safe on 8 GB), derives the 22
    features, applies the >=5-packet rule, caps rows per file and label (random,
    seeded), then drops exact duplicate feature rows (CIC contains many; leaving
    them in leaks identical rows across train/test).
    Returns a DataFrame: 22 features + Label, Attack, is_attack, dst_port, source_file
    """
    files = sorted(glob.glob(os.path.join(dataset_dir, "*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSV files in {dataset_dir}")
    parts, report = [], []
    rng = np.random.RandomState(seed)
    for fp in files:
        raw = pd.read_csv(fp, encoding="cp1252", low_memory=False,
                          usecols=lambda c: c.strip() in RAW_COLS or c.strip() == "Label")
        raw.columns = raw.columns.str.strip()
        missing = [c for c in RAW_COLS if c not in raw.columns]
        if missing:
            raise KeyError(f"{os.path.basename(fp)} is missing columns: {missing}")
        n_raw = len(raw)
        label = normalise_label(raw.pop("Label"))
        num = raw[RAW_COLS].apply(pd.to_numeric, errors="coerce")
        num.replace([np.inf, -np.inf], np.nan, inplace=True)
        ok = num.notna().all(axis=1)
        num, label = num[ok], label[ok]
        feats = cic_to_22(num.drop(columns=["Destination Port"]))
        keep = feats.pop("_tot_pkts") >= min_pkts
        feats = feats[keep].copy()
        feats["Label"] = label[keep].values
        feats["dst_port"] = num.loc[keep.index[keep], "Destination Port"].values
        feats["is_attack"] = (feats["Label"] != "BENIGN").astype("int8")
        feats["source_file"] = os.path.basename(fp)[:28]
        pieces = []
        for flag, cap in ((0, per_file_cap_benign), (1, per_file_cap_malicious)):
            sub = feats[feats["is_attack"] == flag]
            if len(sub) > cap:
                sub = sub.iloc[rng.choice(len(sub), cap, replace=False)]
            pieces.append(sub)
        kept = pd.concat(pieces)
        report.append((os.path.basename(fp), n_raw, int((~ok).sum()), int((~keep).sum()), len(kept)))
        parts.append(kept)
        del raw, num, feats
    df = pd.concat(parts, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates(subset=FEATURE_NAMES + ["is_attack"]).reset_index(drop=True)
    for c in FEATURE_NAMES:
        df[c] = df[c].astype("float32")
    df["Attack"] = df["Label"].str.title().replace({"Benign": "Benign"})
    if verbose:
        print(f"{'file':<46}{'raw':>10}{'NaN/inf':>10}{'<5 pkts':>10}{'kept':>10}")
        for n, a, b, c, d in report:
            print(f"{n:<46}{a:>10,}{b:>10,}{c:>10,}{d:>10,}")
        print(f"\nDuplicates removed : {before - len(df):,}")
        print(f"Final rows         : {len(df):,}  "
              f"(benign {int((df.is_attack == 0).sum()):,} | malicious {int(df.is_attack.sum()):,})")
    return df


def make_splits(df, seed=42, frac=(0.70, 0.15, 0.15), train_cap=None):
    """
    Report 3.2 protocol: benign -> 70% train / 15% val / 15% test;
    test = 15% benign holdout + ALL malicious flows.  Training is benign-only.
    """
    rng = np.random.RandomState(seed)
    ben = df[df.is_attack == 0]
    idx = rng.permutation(len(ben))
    n_tr, n_va = int(frac[0] * len(ben)), int(frac[1] * len(ben))
    tr, va, te = ben.iloc[idx[:n_tr]], ben.iloc[idx[n_tr:n_tr + n_va]], ben.iloc[idx[n_tr + n_va:]]
    if train_cap and len(tr) > train_cap:
        tr = tr.iloc[:train_cap]
    mal = df[df.is_attack == 1]
    test = pd.concat([te, mal], ignore_index=True)
    return tr.reset_index(drop=True), va.reset_index(drop=True), test


# --------------------------------------------------------------------------- #
# 3. Scaler: log1p -> Min-Max(clip) ; pickled with plain scikit-learn objects
# --------------------------------------------------------------------------- #
def build_scaler():
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer, MinMaxScaler
    # Raw CIC features span 9+ orders of magnitude; plain Min-Max would squash
    # almost every flow to ~0.  log1p is monotone, so the pipeline is still
    # "Min-Max normalisation to [0,1]" as the report states.
    return Pipeline([
        ("log1p", FunctionTransformer(np.log1p, validate=False)),
        ("minmax", MinMaxScaler(feature_range=(0, 1), clip=True)),
    ])


# --------------------------------------------------------------------------- #
# 4. Model, threshold, metrics
# --------------------------------------------------------------------------- #
def build_autoencoder(input_dim=22, latent_dim=4, dropout=0.10, lr=1e-3):
    """22 -> 16 -> 8 -> 4 -> 8 -> 16 -> 22  (5 hidden layers, symmetric)."""
    import tensorflow as tf
    from tensorflow.keras import layers, Model
    inp = layers.Input(shape=(input_dim,), name="flow_features")
    x = layers.Dense(16, activation="relu", name="enc_1")(inp)
    x = layers.BatchNormalization(name="enc_bn_1")(x)
    x = layers.Dropout(dropout, name="enc_drop_1")(x)
    x = layers.Dense(8, activation="relu", name="enc_2")(x)
    x = layers.BatchNormalization(name="enc_bn_2")(x)
    x = layers.Dropout(dropout, name="enc_drop_2")(x)
    z = layers.Dense(latent_dim, activation="relu", name="bottleneck")(x)
    x = layers.Dense(8, activation="relu", name="dec_1")(z)
    x = layers.Dense(16, activation="relu", name="dec_2")(x)
    out = layers.Dense(input_dim, activation="sigmoid", name="reconstruction")(x)
    model = Model(inp, out, name="HIDS_Autoencoder")
    model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=lr), loss="mse")
    return model


def recon_error(model, X, batch_size=4096):
    """Per-flow reconstruction MSE (the 'RE' of Report 3.1)."""
    rec = model.predict(X, batch_size=batch_size, verbose=0)
    return np.mean((X - rec) ** 2, axis=1)


def calibrate_threshold(re_benign, k=3.0):
    """Report 3.1:  threshold = max(P99(RE), mean(RE) + k*std(RE))  on benign validation RE."""
    mean, std = float(np.mean(re_benign)), float(np.std(re_benign))
    p99 = float(np.percentile(re_benign, 99))
    return {"mean": mean, "std": std, "p99": p99, "k": float(k),
            "threshold": max(p99, mean + k * std)}


def compute_metrics(y_true, score, thr):
    from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                                 f1_score, precision_score, recall_score, roc_auc_score)
    y_pred = (score > thr).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    two = len(np.unique(y_true)) > 1
    return {
        "n": int(len(y_true)), "n_malicious": int(np.sum(y_true)),
        "prevalence": float(np.mean(y_true)),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "roc_auc": float(roc_auc_score(y_true, score)) if two else float("nan"),
        "pr_auc": float(average_precision_score(y_true, score)) if two else float("nan"),
    }


def make_numpy_forward(model):
    """Pure-NumPy inference (BatchNorm folded) - used for the latency benchmark."""
    ops = []
    for l in model.layers:
        cn = l.__class__.__name__
        if cn == "Dense":
            W, b = l.get_weights()
            ops.append(("dense", W.astype("float32"), b.astype("float32"), l.activation.__name__))
        elif cn == "BatchNormalization":
            g, be, m, v = l.get_weights()
            sc = g / np.sqrt(v + l.epsilon)
            ops.append(("bn", sc.astype("float32"), (be - m * sc).astype("float32")))

    def forward(x):
        for op in ops:
            if op[0] == "dense":
                x = x @ op[1] + op[2]
                if op[3] == "relu":
                    x = np.maximum(x, 0)
                elif op[3] == "sigmoid":
                    x = 1.0 / (1.0 + np.exp(-x))
            else:
                x = x * op[1] + op[2]
        return x
    return forward


# --------------------------------------------------------------------------- #
# 5. Per-flow Scapy extractor (same 22 definitions, durations in microseconds)
# --------------------------------------------------------------------------- #
def _flow_features(rec):
    n = rec["n"]
    if n < MIN_PKTS:
        return None
    t = np.asarray(rec["times"], dtype="float64")
    L = np.asarray(rec["lens"], dtype="float64")
    fwd = np.asarray(rec["fwd"], dtype=bool)
    if fwd.sum() < 1 or len(t) < 2:
        return None
    dur_s = max(t[-1] - t[0], 1e-6)
    iat = np.diff(t)
    ft = t[fwd]
    fiat = np.diff(ft) if len(ft) > 1 else np.zeros(1)
    fl = L[fwd]
    ttl = np.asarray(rec["ttl"], dtype="float64")
    tcp_pk = np.asarray(rec["is_tcp"], dtype=bool)
    flg = np.asarray(rec["flags"], dtype=int)
    us = 1e6
    f = [
        dur_s * us, fiat.mean() * us, fiat.std() * us, fiat.min() * us, fiat.max() * us, fiat.sum() * us,
        fl.mean(), fl.std(), fl.min(), fl.max(), fl.sum(),
        n / dur_s, rec["bytes"] / dur_s,
        L.var(), float(np.mean(iat < iat.mean())), float(iat[iat < 1.0].sum() / dur_s),
        float(fwd.sum()), float(len(np.unique(ttl))), float(ttl.mean()),
        float(np.mean((flg[tcp_pk] & 0x12) > 0)) if tcp_pk.any() else 0.0,
        float(rec["proto"] == 17), float(rec["proto"] == 6),
    ]
    return np.asarray(f, dtype="float32")


def extract_flows_from_pcap(path, max_packets=200_000, max_pkts_per_flow=1000, flow_timeout_s=120.0):
    """Streams a PCAP, groups packets into bidirectional 5-tuple flows (forward =
    direction of the first packet), returns an (n_flows, 22) float32 array."""
    from scapy.all import IP, TCP, UDP, PcapReader
    flows, out, seen = {}, [], 0

    def close(rec):
        f = _flow_features(rec)
        if f is not None:
            out.append(f)

    with PcapReader(path) as rd:
        for pkt in rd:
            seen += 1
            if seen > max_packets:
                break
            if IP not in pkt:
                continue
            ip = pkt[IP]
            if TCP in pkt:
                sp, dp, proto, flg = pkt[TCP].sport, pkt[TCP].dport, 6, int(pkt[TCP].flags)
            elif UDP in pkt:
                sp, dp, proto, flg = pkt[UDP].sport, pkt[UDP].dport, 17, 0
            else:
                continue
            ts, ln = float(pkt.time), len(pkt)
            a, b = (ip.src, sp), (ip.dst, dp)
            key = (a, b, proto) if a <= b else (b, a, proto)
            rec = flows.get(key)
            if rec is not None and ts - rec["last"] > flow_timeout_s:
                close(flows.pop(key))
                rec = None
            if rec is None:
                rec = dict(src=a, times=[], lens=[], fwd=[], ttl=[], flags=[], is_tcp=[],
                           proto=proto, last=ts, n=0, bytes=0.0)
                flows[key] = rec
            rec["n"] += 1
            rec["last"] = ts
            rec["bytes"] += ln
            if rec["n"] <= max_pkts_per_flow:
                rec["times"].append(ts); rec["lens"].append(ln)
                rec["fwd"].append(a == rec["src"]); rec["ttl"].append(ip.ttl)
                rec["flags"].append(flg); rec["is_tcp"].append(proto == 6)
    for rec in flows.values():
        close(rec)
    return np.vstack(out) if out else np.empty((0, 22), dtype="float32")
