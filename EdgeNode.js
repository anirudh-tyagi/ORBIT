// ═══════════════════════════════════════════════════════════════════════════
// ORBIT Framework — Edge Node
// Implements: NMT management, UCB1 routing, anomaly detection,
// trust management, adaptive threshold & block size computation
// ═══════════════════════════════════════════════════════════════════════════

import express from 'express';
import cors from 'cors';
import { ethers } from 'ethers';
import { createRequire } from 'module';
import ORBIT_CONFIG from './orbit.config.js';

const require = createRequire(import.meta.url);
let abi;
try {
    abi = require('./artifacts/contracts/ORBIT.sol/ORBIT.json').abi;
} catch {
    try {
        abi = require('./artifacts/contracts/BPRSec.sol/BPRSec.json').abi;
    } catch {
        console.warn('[EdgeNode] No contract ABI found — running without blockchain integration');
        abi = null;
    }
}

const CFG = ORBIT_CONFIG;
const app = express();
app.use(cors());
app.use(express.json());

// ─── Blockchain connection ─────────────────────────────────────────────
const provider = new ethers.JsonRpcProvider(CFG.network.rpcUrl);
const signer = new ethers.Wallet(CFG.network.edgeNode.walletKey, provider);
const contract = abi
    ? new ethers.Contract(CFG.contract.address, abi, signer)
    : null;

// ─── Node Metrics Table (NMT) ──────────────────────────────────────────
// Per the paper Section 2.1.5:
// NMT = { node_id: { success_rate, avg_latency, drop_rate,
//                     invalid_sig_count, trust_score, packets_forwarded,
//                     last_updated } }
const NMT = {};
const routingHistory = {};    // per-node arrays for sliding window
const ucbState = {};          // UCB1 state per routing pair
const anomalyLog = [];        // detected anomalies
const trustHistory = {};      // trust score evolution over time
const networkLoadHistory = []; // ρ(t) over time
const blockSizeHistory = [];  // B(t) over time

// ─── Network Load State ────────────────────────────────────────────────
let rhoSmooth = 0.0;          // smoothed network load ρ_smooth(t)
let activePackets = 0;        // P_active(t)
const P_MAX = CFG.packet.maxPackets || 70;
let epoch = 0;

// ─── Initialize NMT for all IoT nodes ──────────────────────────────────
function initializeNMT() {
    CFG.network.iotNodes.forEach(node => {
        NMT[node.address] = {
            success_rate: 0.8,
            avg_latency: 100,
            drop_rate: 0.0,
            invalid_sig_count: 0,
            trust_score: CFG.trust.initialTrust / 1000 || 0.8,
            packets_forwarded: 0,
            last_updated: Date.now(),
            clean_epochs: 0,        // consecutive epochs without anomaly
            is_malicious: false,
        };
        routingHistory[node.address] = {
            successes: [],
            latencies: [],
            drops: [],
            forwardCounts: [],
        };
        ucbState[node.address] = {
            mean_score: 0.5,
            selection_count: 1,     // avoid division by zero
        };
        trustHistory[node.address] = [{ time: Date.now(), score: 0.8 }];
    });
    console.log(`[EdgeNode] NMT initialized for ${CFG.network.iotNodes.length} IoT nodes`);
}

// ─── Sliding Window Metric Estimation (Eqs. 14–16) ────────────────────
function updateMetrics(nodeAddr, event) {
    const nmt = NMT[nodeAddr];
    if (!nmt) return;

    const hist = routingHistory[nodeAddr];
    const W = CFG.routing.slidingWindowSize;
    const λ = CFG.routing.emaSmoothing;

    // Record event
    hist.successes.push(event.success ? 1 : 0);
    hist.latencies.push(event.latency || 100);
    hist.drops.push(event.dropped ? 1 : 0);

    // Trim to window size
    if (hist.successes.length > W) hist.successes.shift();
    if (hist.latencies.length > W) hist.latencies.shift();
    if (hist.drops.length > W) hist.drops.shift();

    // R_ij(t) — Eq. 15: sliding window success rate
    nmt.success_rate = hist.successes.reduce((a, b) => a + b, 0) / hist.successes.length;

    // L_ij(t) — Eq. 14: EMA latency
    nmt.avg_latency = λ * nmt.avg_latency + (1 - λ) * (event.latency || 100);

    // D_ij(t) — Eq. 16: sliding window drop rate
    nmt.drop_rate = hist.drops.reduce((a, b) => a + b, 0) / hist.drops.length;

    // Invalid sig count
    if (event.invalidSig) {
        nmt.invalid_sig_count++;
    }

    // Packets forwarded
    if (event.success) {
        nmt.packets_forwarded++;
    }

    nmt.last_updated = Date.now();
}

// ─── Sliding Window Weight Adaptation (Eqs. 22–23) ────────────────────
function computeAdaptiveWeights() {
    const W = CFG.routing.slidingWindowSize;
    const ε = 1e-6;

    // Collect all nodes' recent metrics
    const allR = [], allL = [], allD = [];
    Object.values(NMT).forEach(nmt => {
        allR.push(nmt.success_rate);
        allL.push(nmt.avg_latency);
        allD.push(nmt.drop_rate);
    });

    const variance = (arr) => {
        if (arr.length < 2) return ε;
        const mean = arr.reduce((a, b) => a + b, 0) / arr.length;
        return arr.reduce((sum, val) => sum + (val - mean) ** 2, 0) / arr.length;
    };

    const varR = variance(allR);
    const varL = variance(allL);
    const varD = variance(allD);

    // w̃_k = 1 / (Var_W(m_k) + ε)
    const wTildeR = 1 / (varR + ε);
    const wTildeL = 1 / (varL + ε);
    const wTildeD = 1 / (varD + ε);
    const total = wTildeR + wTildeL + wTildeD;

    return {
        w1: wTildeR / total,  // reliability weight
        w2: wTildeL / total,  // latency weight
        w3: wTildeD / total,  // drop rate weight
    };
}

// ─── Routing Score Computation (Eqs. 12–13) ────────────────────────────
function computeRoutingScore(nodeAddr) {
    const nmt = NMT[nodeAddr];
    if (!nmt || nmt.is_malicious) return -Infinity;

    const weights = computeAdaptiveWeights();

    // S_ij = w1·R - w2·L_normalized - w3·D
    const maxLatency = Math.max(...Object.values(NMT).map(n => n.avg_latency), 1);
    const normalizedLatency = nmt.avg_latency / maxLatency;

    const S = weights.w1 * nmt.success_rate
            - weights.w2 * normalizedLatency
            - weights.w3 * nmt.drop_rate;

    // Ŝ = S · T (trust-weighted) — Eq. 13
    return S * nmt.trust_score;
}

// ─── UCB1 Next-Hop Selection (Eq. 21) ──────────────────────────────────
function selectNextHop(currentNode, neighbors) {
    if (!neighbors || neighbors.length === 0) return null;

    const t = epoch + 1;
    let bestNode = null;
    let bestUCB = -Infinity;

    neighbors.forEach(neighborAddr => {
        const nmt = NMT[neighborAddr];
        if (!nmt || nmt.is_malicious) return;

        const ucb = ucbState[neighborAddr] || { mean_score: 0.5, selection_count: 1 };
        const score = computeRoutingScore(neighborAddr);

        // UCB1: j* = argmax [ μ̂_j + sqrt(2·ln(t) / n_j) ]
        const explorationBonus = Math.sqrt(
            (CFG.routing.ucb1ExplorationConstant * Math.log(t)) / ucb.selection_count
        );

        const ucbValue = score + explorationBonus;

        if (ucbValue > bestUCB) {
            bestUCB = ucbValue;
            bestNode = neighborAddr;
        }
    });

    // Update UCB1 state for selected node
    if (bestNode && ucbState[bestNode]) {
        ucbState[bestNode].selection_count++;
        const n = ucbState[bestNode].selection_count;
        const reward = computeRoutingScore(bestNode);
        // Incremental mean update: μ̂ = μ̂ + (1/n)(reward - μ̂)
        ucbState[bestNode].mean_score += (1 / n) * (reward - ucbState[bestNode].mean_score);
    }

    return bestNode;
}

// ─── Anomaly Detection (Eqs. 30–37) ───────────────────────────────────
function detectAnomalies(nodeAddr) {
    const nmt = NMT[nodeAddr];
    if (!nmt || nmt.is_malicious) return null;

    const allNodes = Object.values(NMT).filter(n => !n.is_malicious);
    const CFG_A = CFG.anomaly;

    // Network-wide statistics
    const meanDrop = allNodes.reduce((s, n) => s + n.drop_rate, 0) / allNodes.length;
    const stdDrop = Math.sqrt(
        allNodes.reduce((s, n) => s + (n.drop_rate - meanDrop) ** 2, 0) / allNodes.length
    );
    const meanLatency = allNodes.reduce((s, n) => s + n.avg_latency, 0) / allNodes.length;

    const anomalies = { A1: false, A2: false, A3: false, A4: false };

    // Condition 1: Excessive Drop Rate — Eq. 30
    const θ_D = meanDrop + CFG_A.dropSensitivity * stdDrop;
    if (nmt.drop_rate > θ_D && nmt.drop_rate > 0.05) {
        anomalies.A1 = true;
    }

    // Condition 2: Invalid Signature Threshold — Eq. 32
    if (nmt.invalid_sig_count > CFG_A.invalidSigLimit) {
        anomalies.A2 = true;
    }

    // Condition 3: Latency Deviation — Eq. 34
    const Λ = meanLatency > 0 ? (nmt.avg_latency - meanLatency) / meanLatency : 0;
    if (Λ > CFG_A.latencyDeviation) {
        anomalies.A3 = true;
    }

    // Condition 4: Forwarding Inconsistency — Eq. 34
    const hist = routingHistory[nodeAddr];
    if (hist && hist.forwardCounts.length >= 3) {
        const mean = hist.forwardCounts.reduce((a, b) => a + b, 0) / hist.forwardCounts.length;
        const std = Math.sqrt(
            hist.forwardCounts.reduce((s, v) => s + (v - mean) ** 2, 0) / hist.forwardCounts.length
        );
        const Ψ = mean > 0 ? std / mean : 0;
        if (Ψ > CFG_A.consistencyLimit) {
            anomalies.A4 = true;
        }
    }

    // Composite anomaly score — Eq. 35
    const v = CFG_A.votingWeights;
    const compositeScore = (anomalies.A1 ? v.dropRate : 0)
                         + (anomalies.A2 ? v.invalidSig : 0)
                         + (anomalies.A3 ? v.latencyDev : 0)
                         + (anomalies.A4 ? v.consistency : 0);

    const result = {
        nodeAddr,
        anomalies,
        compositeScore,
        isMalicious: compositeScore >= CFG_A.maliciousThreshold,
        timestamp: Date.now(),
    };

    if (anomalies.A1 || anomalies.A2 || anomalies.A3 || anomalies.A4) {
        anomalyLog.push(result);
        console.log(`[EdgeNode] ⚠ Anomaly detected for ${nodeAddr}: score=${compositeScore.toFixed(3)}`);
    }

    return result;
}

// ─── Trust Score Update (Eqs. 38–43) ──────────────────────────────────
function updateTrustScore(nodeAddr) {
    const nmt = NMT[nodeAddr];
    if (!nmt) return;

    const αT = CFG.trust.updateRate;
    const φ = CFG.trust.feedbackWeights;

    // Instantaneous trust feedback — Eq. 39
    const meanLatency = Object.values(NMT).reduce((s, n) => s + n.avg_latency, 0)
                      / Object.keys(NMT).length || 1;
    const Λ_clipped = Math.min((nmt.avg_latency - meanLatency) / Math.max(meanLatency, 1), 1);

    const F_T = φ.successRate * nmt.success_rate
              + φ.dropRate * (1 - nmt.drop_rate)
              + φ.latency * (1 - Math.max(0, Λ_clipped));

    // EMA trust update — Eq. 38
    nmt.trust_score = nmt.trust_score * (1 - αT) + αT * F_T;

    // Apply anomaly penalties — Eq. 41
    const anomalyResult = detectAnomalies(nodeAddr);
    if (anomalyResult) {
        const p = CFG.trust.penalties;
        let penalty = 0;
        if (anomalyResult.anomalies.A1) penalty += p.dropRate;
        if (anomalyResult.anomalies.A2) penalty += p.invalidSig;
        if (anomalyResult.anomalies.A3) penalty += p.latencyDev;
        if (anomalyResult.anomalies.A4) penalty += p.consistency;

        if (penalty > 0) {
            nmt.trust_score = Math.max(0, nmt.trust_score - penalty);
            nmt.clean_epochs = 0;
        } else {
            nmt.clean_epochs++;
        }

        // Malicious classification — Eq. 37
        if (anomalyResult.isMalicious) {
            nmt.is_malicious = true;
            nmt.trust_score = 0;
            console.log(`[EdgeNode] 🚫 Node ${nodeAddr} classified as MALICIOUS`);
        }
    }

    // Recovery mechanism — Eq. 43
    if (nmt.trust_score < CFG.trust.warningThreshold
        && !nmt.is_malicious
        && nmt.clean_epochs >= CFG.trust.recoveryWindow) {
        nmt.trust_score = Math.min(1, nmt.trust_score + CFG.trust.recoveryIncrement);
        console.log(`[EdgeNode] ✅ Trust recovery for ${nodeAddr}: ${nmt.trust_score.toFixed(3)}`);
    }

    // Clamp
    nmt.trust_score = Math.max(0, Math.min(1, nmt.trust_score));

    // Record history
    if (!trustHistory[nodeAddr]) trustHistory[nodeAddr] = [];
    trustHistory[nodeAddr].push({ time: Date.now(), score: nmt.trust_score });
    if (trustHistory[nodeAddr].length > 200) trustHistory[nodeAddr].shift();
}

// ─── Adaptive Root Packet Threshold (Eq. 47) ──────────────────────────
function computeAdaptiveThreshold() {
    const λρ = CFG.adaptive.loadSmoothing;

    // ρ(t) = P_active / P_max
    const rho = Math.min(activePackets / P_MAX, 1);

    // Smoothed: ρ_smooth = λ_ρ · ρ_smooth(t-1) + (1-λ_ρ) · ρ(t)
    rhoSmooth = λρ * rhoSmooth + (1 - λρ) * rho;

    // θ(t) = θ_base / (1 + ρ_smooth)
    const θ_raw = CFG.adaptive.baseThreshold / (1 + rhoSmooth);

    // Clamp
    const θ = Math.max(CFG.adaptive.minThreshold, Math.min(CFG.adaptive.maxThreshold, θ_raw));

    networkLoadHistory.push({ time: Date.now(), rho: rhoSmooth, theta: θ });
    if (networkLoadHistory.length > 200) networkLoadHistory.shift();

    return θ;
}

// ─── Adaptive Block Size (Eq. 55) ──────────────────────────────────────
function computeAdaptiveBlockSize() {
    const B_raw = CFG.block.baseSize * (1 - rhoSmooth);
    const B_round = Math.round(B_raw);
    const B = Math.max(CFG.block.minSize, Math.min(CFG.block.maxSize, B_round));

    blockSizeHistory.push({ time: Date.now(), size: B, rho: rhoSmooth });
    if (blockSizeHistory.length > 200) blockSizeHistory.shift();

    return B;
}

// ─── Epoch Tick (periodic update) ──────────────────────────────────────
function epochTick() {
    epoch++;
    Object.keys(NMT).forEach(addr => {
        const hist = routingHistory[addr];
        if (hist) {
            hist.forwardCounts.push(NMT[addr].packets_forwarded);
            if (hist.forwardCounts.length > 20) hist.forwardCounts.shift();
        }
        updateTrustScore(addr);

        // Sync NMT snapshot to blockchain smart contract per Section 2.1.5 / Table 5
        if (contract && typeof contract.updateNMT === 'function') {
            const nmt = NMT[addr];
            contract.updateNMT(
                addr,
                Math.round(nmt.success_rate * 1000),
                Math.round(nmt.avg_latency),
                Math.round(nmt.drop_rate * 1000),
                Math.round(nmt.trust_score * 1000),
                nmt.packets_forwarded
            ).catch(() => {});
        }
    });
    console.log(`[EdgeNode] Epoch ${epoch} — ρ=${rhoSmooth.toFixed(3)}, θ=${computeAdaptiveThreshold().toFixed(3)}, B=${computeAdaptiveBlockSize()}`);
}

// Run epoch every 10 seconds
setInterval(epochTick, 10000);

// ─── Express API Endpoints ─────────────────────────────────────────────

// GET /bestNextHop?current=10.0.0.1
app.get('/bestNextHop', (req, res) => {
    const current = req.query.current;
    const neighbors = CFG.network.iotNodes
        .map(n => n.address)
        .filter(a => a !== current);
    const bestHop = selectNextHop(current, neighbors);
    const θ = computeAdaptiveThreshold();
    const B = computeAdaptiveBlockSize();

    res.json({
        nextHop: bestHop,
        threshold: θ,
        blockSize: B,
        rhoSmooth,
        epoch,
    });
});

// POST /reportEvent — IoT node reports a routing event
app.post('/reportEvent', (req, res) => {
    const { nodeAddr, success, latency, dropped, invalidSig } = req.body;
    updateMetrics(nodeAddr, { success, latency, dropped, invalidSig });

    if (success) activePackets = Math.max(0, activePackets - 1);
    else activePackets++;

    res.json({ status: 'ok', trustScore: NMT[nodeAddr]?.trust_score });
});

// POST /packetGenerated — track active packets
app.post('/packetGenerated', (req, res) => {
    activePackets++;
    res.json({ activePackets, rhoSmooth });
});

// GET /nmt — full NMT data
app.get('/nmt', (req, res) => {
    res.json(NMT);
});

// GET /trustHistory
app.get('/trustHistory', (req, res) => {
    res.json(trustHistory);
});

// GET /anomalies
app.get('/anomalies', (req, res) => {
    res.json(anomalyLog.slice(-50));
});

// GET /networkLoad
app.get('/networkLoad', (req, res) => {
    res.json({
        current: { rho: rhoSmooth, theta: computeAdaptiveThreshold(), blockSize: computeAdaptiveBlockSize() },
        history: networkLoadHistory,
    });
});

// GET /blockSizeHistory
app.get('/blockSizeHistory', (req, res) => {
    res.json(blockSizeHistory);
});

// GET /routingScores
app.get('/routingScores', (req, res) => {
    const scores = {};
    Object.keys(NMT).forEach(addr => {
        scores[addr] = {
            rawScore: computeRoutingScore(addr),
            ucbState: ucbState[addr],
            metrics: NMT[addr],
        };
    });
    res.json(scores);
});

// GET /lrc — Local Routing Cache snapshot for IoT nodes
app.get('/lrc', (req, res) => {
    const lrc = {};
    Object.keys(NMT).forEach(addr => {
        lrc[addr] = {
            success_rate: NMT[addr].success_rate,
            avg_latency: NMT[addr].avg_latency,
            drop_rate: NMT[addr].drop_rate,
            trust_score: NMT[addr].trust_score,
        };
    });
    res.json({
        lrc,
        timestamp: Date.now(),
        threshold: computeAdaptiveThreshold(),
        blockSize: computeAdaptiveBlockSize(),
    });
});

// ─── Start Server ──────────────────────────────────────────────────────
initializeNMT();
const PORT = CFG.network.edgeNode.httpPort;
app.listen(PORT, () => {
    console.log(`[EdgeNode] ORBIT Edge Node running on port ${PORT}`);
    console.log(`[EdgeNode] Managing ${CFG.network.iotNodes.length} IoT nodes`);
});
