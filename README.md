# ORBIT — Optimized Routing with Blockchain and Intelligent Trust

> A blockchain-based IoT routing protocol for smart city networks using Proof-of-Routing (PoR) consensus, UCB1 Multi-Armed Bandit adaptive routing, composite anomaly detection, and performance-based cryptocurrency reward distribution.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ORBIT Network                             │
│                                                                  │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌───────┐│
│  │IoTNode 1│  │IoTNode 2│  │IoTNode 3│  │IoTNode 4│  │IoTN. 5││
│  │10.0.0.1 │  │10.0.0.2 │  │10.0.0.3 │  │10.0.0.4 │  │10.0.0.5│
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └───┬───┘│
│       │            │            │            │            │     │
│       └────────────┴──────┬─────┴────────────┴────────────┘     │
│                           │ TCP (Port 8080)                      │
│                    ┌──────┴──────┐                               │
│                    │  Server.js  │ ← Coordinator + Dashboard API │
│                    │  (Port 8081)│                               │
│                    └─────────────┘                               │
│                                                                  │
│  ┌───────────────┐              ┌──────────────┐                │
│  │   EdgeNode    │  HTTP ←→     │  BlockNode   │                │
│  │  (Port 9090)  │              │  (Port 9091) │                │
│  │ UCB1 + NMT +  │              │ Adaptive     │                │
│  │ Anomaly Det.  │              │ Block Form.  │                │
│  └───────────────┘              └──────────────┘                │
│                                                                  │
│  ┌─────────────────────────────────────────────┐                │
│  │        Hardhat Local Blockchain             │                │
│  │  ORBIT.sol — Smart Contract (PoR Consensus) │                │
│  └─────────────────────────────────────────────┘                │
└──────────────────────────────────────────────────────────────────┘
```

## Key Features (from paper)

| Feature | Implementation |
|---------|---------------|
| **UCB1 Routing** | Multi-Armed Bandit next-hop selection via EdgeNode |
| **Anomaly Detection** | 4-condition composite (drop rate, invalid sig, latency, consistency) |
| **Trust Management** | EMA-based trust scores with penalty & recovery mechanisms |
| **Adaptive Thresholds** | Root packet selection adapts to network load θ(t) |
| **Adaptive Blocks** | Block size varies 5–20 based on load B(t) |
| **Performance Rewards** | Q = 0.35F + 0.30R − 0.15d̄ + 0.20T |
| **BLS Signatures** | Cryptographic authentication at every hop |
| **Blake3 Hashing** | Fast packet integrity verification |

## Prerequisites

- **Node.js** 18+
- **Python** 3.10+ (for simulation data)
- **npm** packages (installed via `npm install`)

## Quick Start

### 1. Install Dependencies
```bash
npm install
pip install numpy pandas   # For simulation scripts
```

### 2. Start Hardhat Blockchain
```bash
npm run chain
```

### 3. Compile & Deploy Smart Contract
```bash
# In a new terminal
npm run compile
npm run deploy
```

### 4. Start ORBIT Nodes
```bash
# Terminal 1 — Edge Node (UCB1 routing + anomaly detection)
npm run start:edge

# Terminal 2 — Block Node (adaptive block formation)
npm run start:block

# Terminal 3 — Coordinator Server + Dashboard API
npm run start

# Terminals 4–8 — IoT Nodes (one per terminal)
npm run start:node1
npm run start:node2
npm run start:node3
npm run start:node4
npm run start:node5
```

### 5. Open Dashboard
Open `index.html` in your browser to see the ORBIT Network Dashboard.

### 6. Run Simulation Data Generator
```bash
npm run simulate
```

## Project Structure

```
BPRSec-master/
├── Server.js              # Coordinator — packet dispatch + dashboard API
├── EdgeNode.js            # Edge Node — UCB1, NMT, anomaly detection, trust
├── BlockNode.js           # Block Node — adaptive block formation
├── IoTNode.js             # Configurable IoT relay node (replaces Server_2–6)
├── orbit.config.js        # Centralized ORBIT parameters (Appendix A.4)
├── index.html             # Premium ORBIT Network Dashboard
├── contracts/
│   └── ORBIT.sol          # Smart contract — performance-based rewards
├── scripts/
│   └── deploy.cjs         # Contract deployment + node registration
├── ml/
│   ├── generate_synthetic_data.py  # Simulation data generator
│   └── data/                       # Generated CSV/JSON datasets
├── hardhat.config.cjs     # Hardhat blockchain configuration
├── package.json           # Dependencies and scripts
└── iot_data.json          # IoT sensor packet data
```

## Configuration

All ORBIT parameters are centralized in [`orbit.config.js`](orbit.config.js), matching the paper's Appendix A.4 (Table 6). Key parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `routing.emaSmoothing` | 0.7 | EMA smoothing factor (λ) |
| `routing.slidingWindowSize` | 50 | Sliding window size (W) |
| `anomaly.dropSensitivity` | 2.0 | Drop rate threshold (κ_D) |
| `trust.updateRate` | 0.3 | Trust EMA rate (α_T) |
| `adaptive.baseThreshold` | 0.5 | Root packet threshold (θ_base) |
| `block.minSize` / `maxSize` | 5 / 20 | Adaptive block bounds |

## Dashboard

The ORBIT dashboard (`index.html`) provides real-time visualization of:

1. **Packet Delivery Ratio** — PDR gauge
2. **Token Distribution** — Performance-based allocation per node
3. **Trust Score Evolution** — Per-node trust over time
4. **Adaptive Threshold vs Load** — θ(t) and ρ(t) dual-axis chart
5. **Block Formation** — Adaptive block sizes
6. **Node Metrics Table** — Full NMT with routing scores
7. **Anomaly Detection Log** — Detected anomalies with composite scores

## References

Based on the ORBIT framework paper describing a blockchain-based IoT routing protocol with Proof-of-Routing consensus for smart city networks.
