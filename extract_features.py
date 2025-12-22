#!/usr/bin/env python3
from scapy.all import PcapReader, UDP
import os, glob, math, random
import numpy as np
import pandas as pd
from collections import Counter

WIN = 0.5  # seconds (non-overlap)
SEED = 42
TARGET_PER_SCENARIO = 2000

def window_features(pkt_sizes, src_ports, ts_list):
    """Compute 9 features for one window."""
    n = len(pkt_sizes)
    if n == 0:
        return {
            "pkt_in": 0,
            "byte_in": 0,
            "avg_len": 0.0,
            "std_len": 0.0,
            "same_size_ratio": 0.0,
            "unique_src_port": 0,
            "top_port_pkt": 0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
        }

    sizes = np.array(pkt_sizes, dtype=np.float64)
    pkt_in = int(n)
    byte_in = int(sizes.sum())
    avg_len = float(sizes.mean())
    std_len = float(sizes.std())

    # same_size_ratio: mode(size)/n
    size_counts = Counter(pkt_sizes)
    same_size_ratio = float(max(size_counts.values()) / n) if n > 0 else 0.0

    # ports
    port_counts = Counter(src_ports)
    unique_src_port = int(len(port_counts))
    top_port_pkt = int(max(port_counts.values())) if port_counts else 0

    # IAT in ms inside window
    if len(ts_list) >= 2:
        iats = np.diff(np.array(ts_list, dtype=np.float64)) * 1000.0
        iat_mean = float(iats.mean()) if len(iats) else 0.0
        iat_std = float(iats.std()) if len(iats) else 0.0
    else:
        iat_mean, iat_std = 0.0, 0.0

    return {
        "pkt_in": pkt_in,
        "byte_in": byte_in,
        "avg_len": avg_len,
        "std_len": std_len,
        "same_size_ratio": same_size_ratio,
        "unique_src_port": unique_src_port,
        "top_port_pkt": top_port_pkt,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
    }

def extract_windows_from_pcap(pcap_path):
    """
    Turn a raw pcap into fixed 0.5s non-overlap windows.
    IMPORTANT: We keep empty windows too (pkt_in=0), especially needed for sparse scenario.
    """
    rows = []

    reader = PcapReader(pcap_path)
    first_pkt = None

    # Find first UDP packet time (or first packet time)
    for pkt in reader:
        first_pkt = pkt
        break
    if first_pkt is None:
        reader.close()
        return rows

    t0 = float(first_pkt.time)
    # rewind not supported -> start processing including first_pkt
    reader.close()
    reader = PcapReader(pcap_path)

    # current window
    w_idx = 0
    w_start = t0
    w_end = w_start + WIN

    pkt_sizes = []
    src_ports = []
    ts_list = []

    def flush_window(wi):
        feats = window_features(pkt_sizes, src_ports, ts_list)
        feats["window_idx"] = wi
        rows.append(feats)

    for pkt in reader:
        t = float(pkt.time)

        # advance windows until pkt fits
        while t >= w_end:
            flush_window(w_idx)
            w_idx += 1
            w_start = w_end
            w_end = w_start + WIN
            pkt_sizes.clear()
            src_ports.clear()
            ts_list.clear()

        # collect only UDP packets (expected)
        if UDP in pkt:
            pkt_sizes.append(len(pkt))
            src_ports.append(int(pkt[UDP].sport))
            ts_list.append(t)

    # flush last window (the one containing last pkt)
    flush_window(w_idx)

    reader.close()
    return rows

def scenario_from_name(fname):
    base = os.path.basename(fname)
    # expected: r3_s1_..., r3_s2_..., ...
    if base.startswith("r3_s1_"): return "s1"
    if base.startswith("r3_s2_"): return "s2"
    if base.startswith("r3_s3_"): return "s3"
    if base.startswith("r3_s4_"): return "s4"
    if base.startswith("r3_s5_"): return "s5"
    return "unknown"

def main():
    random.seed(SEED)

    pcaps = sorted(glob.glob("/root/datasets/benign_raw/r3_s*.pcap"))
    if not pcaps:
        print("[!] No r3_s*.pcap found in /root/datasets/benign_raw/")
        return

    all_rows = []
    print("="*80)
    print("Benign r3 raw PCAP -> 0.5s windows -> 9 features -> scenario 2000 each")
    print("="*80)

    # Extract windows per scenario
    scenario_rows = {f"s{i}": [] for i in range(1,6)}

    for p in pcaps:
        scen = scenario_from_name(p)
        print(f"\n[*] Reading: {os.path.basename(p)}  (scenario={scen})")
        rows = extract_windows_from_pcap(p)
        print(f"    windows extracted: {len(rows)}")

        # Add metadata
        for r in rows:
            r["scenario"] = scen
            r["group_id"] = os.path.basename(p)  # for GroupKFold later (avoid leakage)
            r["label"] = 0  # benign
        if scen in scenario_rows:
            scenario_rows[scen].extend(rows)
        else:
            print(f"    [!] Unknown scenario name: {scen} (skipped)")

    # Sample exactly 2000 per scenario
    final_rows = []
    for scen in ["s1","s2","s3","s4","s5"]:
        rows = scenario_rows[scen]
        if len(rows) < TARGET_PER_SCENARIO:
            print(f"[!] {scen}: only {len(rows)} windows < {TARGET_PER_SCENARIO}. (Need more capture)")
            # still take all; better than failing hard
            chosen = rows
        else:
            chosen = random.sample(rows, TARGET_PER_SCENARIO)

        print(f"[+] {scen}: using {len(chosen)} windows")
        final_rows.extend(chosen)

    df = pd.DataFrame(final_rows)

    # Stable column order
    cols = [
        "scenario", "group_id", "window_idx",
        "pkt_in", "byte_in", "avg_len", "std_len", "same_size_ratio",
        "unique_src_port", "top_port_pkt", "iat_mean", "iat_std",
        "label"
    ]
    df = df[cols]

    out_path = "/root/datasets/processed/benign_features.csv"
    df.to_csv(out_path, index=False)
    print("\n" + "="*80)
    print(f"Saved: {out_path}")
    print(df["scenario"].value_counts().sort_index())
    print("="*80)

if __name__ == "__main__":
    main()
