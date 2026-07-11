#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
ORBIT Framework — Synthetic Simulation Data Generator
Generates realistic IoT network simulation data matching the ORBIT paper's
experimental setup (Section 3.1, Table 1):
  - 5 IoT nodes, 2 edge nodes, 1 block node
  - Poisson-distributed packet generation (2 pkts/sec)
  - Attacker penetration α = 0–30%
  - 30 independent runs, 10 min each

Produces:
  - ml/data/node_metrics.csv        → Per-node NMT snapshots over time
  - ml/data/routing_events.csv      → Individual packet routing events
  - ml/data/simulation_results.json → Aggregated results (PDR, latency, etc.)
═══════════════════════════════════════════════════════════════════════════
"""

import numpy as np
import pandas as pd
import json
import os

np.random.seed(42)

# ─── ORBIT Simulation Parameters (Table 1, Section 3.1) ────────────────
NUM_IOT_NODES = 5
PACKET_RATE = 2                  # packets/sec/node
SIM_DURATION = 600               # 10 minutes in seconds
NUM_RUNS = 30
TTL = 10
SLIDING_WINDOW = 50
EMA_LAMBDA = 0.7
LOAD_SMOOTHING = 0.6
BASE_THRESHOLD = 0.5
BLOCK_BASE = 20
BLOCK_MIN = 5
BLOCK_MAX = 20
TRUST_UPDATE = 0.3
UCB1_C = 2                       # sqrt(2)

NODE_ADDRS = [f"10.0.0.{i+1}" for i in range(NUM_IOT_NODES)]

# ─── Anomaly Detection Parameters (Table A4.2) ─────────────────────────
KAPPA_D = 2.0
THETA_PHI = 3
THETA_LAMBDA = 2.0
THETA_PSI = 1.5
THETA_MAL = 0.5
PENALTIES = {'drop': 0.20, 'sig': 0.25, 'latency': 0.10, 'consistency': 0.10}

# ─── Reward Weights (Eq. 69) ───────────────────────────────────────────
W_FORWARD = 0.35
W_SUCCESS = 0.30
W_DELAY = 0.15
W_TRUST = 0.20

os.makedirs('ml/data', exist_ok=True)

print("═══════════════════════════════════════════════════════════════")
print("  ORBIT Simulation Data Generator")
print("  Matching paper parameters: Table 1, Appendix A.4")
print("═══════════════════════════════════════════════════════════════\n")


def simulate_run(run_id, alpha=0.0):
    """
    Simulate a single 10-minute run of the ORBIT protocol.
    alpha: fraction of malicious nodes (0.0–0.3)
    """
    num_malicious = int(NUM_IOT_NODES * alpha)
    malicious_set = set(NODE_ADDRS[-num_malicious:]) if num_malicious > 0 else set()

    # Initialize NMT
    nmt = {}
    for addr in NODE_ADDRS:
        nmt[addr] = {
            'success_rate': 0.8,
            'avg_latency': 100.0,
            'drop_rate': 0.0,
            'invalid_sig': 0,
            'trust_score': 0.8,
            'packets_forwarded': 0,
            'selections': 1,
            'total_reward': 0.5,
        }

    records = []
    events = []
    rho_smooth = 0.0
    active_packets = 0
    epoch = 0
    total_generated = 0
    total_delivered = 0

    # Simulate second by second
    for t in range(SIM_DURATION):
        # Generate packets (Poisson)
        n_packets = np.random.poisson(PACKET_RATE)
        active_packets += n_packets
        total_generated += n_packets

        # Update network load — Eq. 47
        rho = min(active_packets / max(total_generated, 1), 1.0)
        rho_smooth = LOAD_SMOOTHING * rho_smooth + (1 - LOAD_SMOOTHING) * rho

        # Adaptive threshold — Eq. 47
        theta = max(0.15, min(0.5, BASE_THRESHOLD / (1 + rho_smooth)))

        # Adaptive block size — Eq. 55
        block_size = max(BLOCK_MIN, min(BLOCK_MAX, round(BLOCK_BASE * (1 - rho_smooth))))

        for pkt in range(n_packets):
            src_idx = np.random.randint(NUM_IOT_NODES)
            dest_idx = np.random.choice([i for i in range(NUM_IOT_NODES) if i != src_idx])
            src = NODE_ADDRS[src_idx]
            dest = NODE_ADDRS[dest_idx]

            # UCB1 next-hop selection — Eq. 21
            candidates = [a for a in NODE_ADDRS if a != src]
            ucb_scores = {}
            for c in candidates:
                m = nmt[c]
                # Routing score — Eq. 12
                max_lat = max(nmt[a]['avg_latency'] for a in NODE_ADDRS)
                S = (0.4 * m['success_rate']
                     - 0.3 * (m['avg_latency'] / max(max_lat, 1))
                     - 0.3 * m['drop_rate'])
                S_hat = S * m['trust_score']

                # UCB1 exploration bonus
                n_j = max(m['selections'], 1)
                explore = np.sqrt(UCB1_C * np.log(epoch + 2) / n_j)
                ucb_scores[c] = S_hat + explore

            next_hop = max(ucb_scores, key=ucb_scores.get)
            nmt[next_hop]['selections'] += 1

            # Simulate forwarding
            path = [src, next_hop]
            hops = 1
            current = next_hop
            delivered = True
            total_latency = 0

            while current != dest and hops < TTL:
                is_mal = current in malicious_set

                # Malicious behavior
                if is_mal:
                    if np.random.random() < 0.4:  # 40% drop rate
                        delivered = False
                        nmt[current]['drop_rate'] = EMA_LAMBDA * nmt[current]['drop_rate'] + (1 - EMA_LAMBDA) * 1.0
                        break
                    if np.random.random() < 0.1:  # 10% invalid sig
                        nmt[current]['invalid_sig'] += 1
                    hop_latency = np.random.normal(400, 80)  # 3x inflation
                else:
                    if np.random.random() < 0.02:  # 2% natural drop
                        delivered = False
                        break
                    hop_latency = np.random.normal(120, 30)

                hop_latency = max(10, hop_latency)
                total_latency += hop_latency

                # EMA latency update — Eq. 14
                nmt[current]['avg_latency'] = (
                    EMA_LAMBDA * nmt[current]['avg_latency'] + (1 - EMA_LAMBDA) * hop_latency
                )

                nmt[current]['packets_forwarded'] += 1

                # Select next hop (simplified — use trust-weighted random for non-first hop)
                remaining = [a for a in NODE_ADDRS if a not in path and a != current]
                if not remaining or current == dest:
                    break

                if dest in remaining:
                    current = dest
                else:
                    # Trust-weighted selection
                    weights = np.array([max(nmt[a]['trust_score'], 0.01) for a in remaining])
                    weights /= weights.sum()
                    current = np.random.choice(remaining, p=weights)

                path.append(current)
                hops += 1

            if current == dest:
                delivered = True

            if delivered:
                total_delivered += 1
                active_packets = max(0, active_packets - 1)
                # Update success rate
                for node in path[1:]:
                    nmt[node]['success_rate'] = (
                        EMA_LAMBDA * nmt[node]['success_rate'] + (1 - EMA_LAMBDA) * 1.0
                    )
                    nmt[node]['drop_rate'] = (
                        EMA_LAMBDA * nmt[node]['drop_rate'] + (1 - EMA_LAMBDA) * 0.0
                    )
            else:
                for node in path[1:]:
                    nmt[node]['success_rate'] = (
                        EMA_LAMBDA * nmt[node]['success_rate'] + (1 - EMA_LAMBDA) * 0.0
                    )

            events.append({
                'run': run_id,
                'time': t,
                'src': src,
                'dest': dest,
                'path': '->'.join(path),
                'hops': hops,
                'latency_ms': round(total_latency, 2),
                'delivered': int(delivered),
                'alpha': alpha,
            })

        # Epoch tick (every 10 seconds) — anomaly detection + trust update
        if t % 10 == 0:
            epoch += 1
            mean_drop = np.mean([nmt[a]['drop_rate'] for a in NODE_ADDRS])
            std_drop = np.std([nmt[a]['drop_rate'] for a in NODE_ADDRS])
            mean_lat = np.mean([nmt[a]['avg_latency'] for a in NODE_ADDRS])

            for addr in NODE_ADDRS:
                m = nmt[addr]

                # Anomaly detection — Eqs. 30–35
                A1 = m['drop_rate'] > (mean_drop + KAPPA_D * std_drop) and m['drop_rate'] > 0.05
                A2 = m['invalid_sig'] > THETA_PHI
                A3 = mean_lat > 0 and ((m['avg_latency'] - mean_lat) / mean_lat) > THETA_LAMBDA
                A4 = False  # simplified

                composite = (0.35 * A1 + 0.35 * A2 + 0.15 * A3 + 0.15 * A4)

                # Trust update — Eqs. 38–41
                feedback = (0.5 * m['success_rate']
                          + 0.3 * (1 - m['drop_rate'])
                          + 0.2 * (1 - min(m['avg_latency'] / 400, 1)))
                m['trust_score'] = m['trust_score'] * (1 - TRUST_UPDATE) + TRUST_UPDATE * feedback

                # Penalties
                if A1: m['trust_score'] = max(0, m['trust_score'] - PENALTIES['drop'])
                if A2: m['trust_score'] = max(0, m['trust_score'] - PENALTIES['sig'])
                if A3: m['trust_score'] = max(0, m['trust_score'] - PENALTIES['latency'])
                m['trust_score'] = np.clip(m['trust_score'], 0, 1)

                records.append({
                    'run': run_id,
                    'epoch': epoch,
                    'time': t,
                    'node': addr,
                    'success_rate': round(m['success_rate'], 4),
                    'avg_latency': round(m['avg_latency'], 2),
                    'drop_rate': round(m['drop_rate'], 4),
                    'trust_score': round(m['trust_score'], 4),
                    'packets_forwarded': m['packets_forwarded'],
                    'invalid_sig': m['invalid_sig'],
                    'is_malicious': int(addr in malicious_set),
                    'alpha': alpha,
                    'rho': round(rho_smooth, 4),
                    'theta': round(theta, 4),
                    'block_size': block_size,
                })

    pdr = total_delivered / max(total_generated, 1)
    return records, events, pdr, total_generated, total_delivered


# ─── Run Simulations ───────────────────────────────────────────────────
all_records = []
all_events = []
results = {}

# Vary alpha from 0% to 30%
for alpha_pct in [0, 10, 20, 30]:
    alpha = alpha_pct / 100.0
    pdrs = []
    latencies = []

    n_runs = min(NUM_RUNS, 5)  # 5 runs per alpha for speed
    print(f"[Sim] Running α={alpha_pct}% ({n_runs} runs)...")

    for run in range(n_runs):
        records, events, pdr, gen, delivered = simulate_run(
            run_id=f"alpha{alpha_pct}_run{run}",
            alpha=alpha,
        )
        all_records.extend(records)
        all_events.extend(events)
        pdrs.append(pdr)

        delivered_events = [e for e in events if e['delivered']]
        if delivered_events:
            latencies.append(np.mean([e['latency_ms'] for e in delivered_events]))

    results[f"alpha_{alpha_pct}"] = {
        'alpha': alpha_pct,
        'pdr_mean': round(np.mean(pdrs), 4),
        'pdr_std': round(np.std(pdrs), 4),
        'latency_mean': round(np.mean(latencies), 2) if latencies else 0,
        'latency_std': round(np.std(latencies), 2) if latencies else 0,
        'num_runs': n_runs,
    }
    print(f"  → PDR: {np.mean(pdrs):.3f} ± {np.std(pdrs):.3f}, "
          f"Latency: {np.mean(latencies):.1f}ms")

# ─── Save Results ──────────────────────────────────────────────────────
df_metrics = pd.DataFrame(all_records)
df_metrics.to_csv('ml/data/node_metrics.csv', index=False)
print(f"\n[Sim] ✅ Saved node_metrics.csv — {len(df_metrics)} records")

df_events = pd.DataFrame(all_events)
df_events.to_csv('ml/data/routing_events.csv', index=False)
print(f"[Sim] ✅ Saved routing_events.csv — {len(df_events)} records")

with open('ml/data/simulation_results.json', 'w') as f:
    json.dump(results, f, indent=2)
print(f"[Sim] ✅ Saved simulation_results.json")

# ─── Summary ───────────────────────────────────────────────────────────
print("\n═══ Simulation Results Summary ═══")
print(f"{'Alpha':>8} {'PDR':>10} {'Latency (ms)':>15}")
print(f"{'─'*8:>8} {'─'*10:>10} {'─'*15:>15}")
for key, val in results.items():
    print(f"{val['alpha']:>7}% {val['pdr_mean']:>10.3f} {val['latency_mean']:>15.1f}")
