// ═══════════════════════════════════════════════════════════════════════════
// ORBIT Framework — Centralized Configuration
// All parameters from Appendix A.4 of the ORBIT paper
// ═══════════════════════════════════════════════════════════════════════════

const ORBIT_CONFIG = {

    // ─── Network Topology ──────────────────────────────────────────────────
    network: {
        iotNodes: [
            { id: 1, address: '10.0.0.1', walletKey: '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba' },
            { id: 2, address: '10.0.0.2', walletKey: '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a' },
            { id: 3, address: '10.0.0.3', walletKey: '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6' },
            { id: 4, address: '10.0.0.4', walletKey: '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' },
            { id: 5, address: '10.0.0.5', walletKey: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' },
        ],
        edgeNode: {
            address: '10.0.1.1',
            walletKey: '0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0',
            httpPort: 9090,
        },
        blockNode: {
            address: '10.0.2.1',
            walletKey: '0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e',
            httpPort: 9091,
        },
        coordinatorWalletKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
        tcpPort: 8080,
        expressPort: 8081,
        rpcUrl: 'http://127.0.0.1:8545/',
    },

    // ─── A4.1 Routing Parameters ───────────────────────────────────────────
    routing: {
        emaSmoothing: 0.7,            // λ — EMA smoothing factor
        slidingWindowSize: 50,        // W — sliding window for metric estimation
        weights: {
            forwarding: 0.35,         // a — forwarding contribution weight
            success: 0.30,            // b — delivery success weight
            delay: 0.15,              // c — delay penalty weight
            trust: 0.20,              // e — trust score weight
        },
        edgeTimeout: 500,             // τ_timeout — edge response timeout (ms)
        lrcPushInterval: 30000,       // Δt — LRC push interval (ms)
        maxLrcAge: 90000,             // Δt_max — max LRC staleness (ms)
        ucb1ExplorationConstant: 2,   // constant inside sqrt(c * ln(t) / n_j)
    },

    // ─── A4.2 Anomaly Detection Parameters ─────────────────────────────────
    anomaly: {
        dropSensitivity: 2.0,         // κ_D — drop rate threshold sensitivity
        invalidSigLimit: 3,           // θ_Φ — invalid signature threshold
        latencyDeviation: 2.0,        // θ_Λ — latency deviation threshold
        consistencyLimit: 1.5,        // θ_Ψ — forwarding consistency threshold
        maliciousThreshold: 0.5,      // θ_malicious — composite score threshold
        votingWeights: {              // v_i — anomaly condition voting weights
            dropRate: 0.35,
            invalidSig: 0.35,
            latencyDev: 0.15,
            consistency: 0.15,
        },
    },

    // ─── Trust Parameters ──────────────────────────────────────────────────
    trust: {
        updateRate: 0.3,              // α_T — trust update learning rate
        feedbackWeights: {            // φ_i — trust feedback weights
            successRate: 0.5,
            dropRate: 0.3,
            latency: 0.2,
        },
        penalties: {                  // p_i — per-condition penalties
            dropRate: 0.20,
            invalidSig: 0.25,
            latencyDev: 0.10,
            consistency: 0.10,
        },
        warningThreshold: 0.3,        // θ_warn — trust warning threshold
        recoveryIncrement: 0.05,      // δ_recovery — recovery bonus per clean epoch
        recoveryWindow: 10,           // R_window — consecutive clean epochs required
        initialTrust: 0.8,            // initial trust score for new nodes
    },

    // ─── A4.3 Adaptive Threshold Parameters ────────────────────────────────
    adaptive: {
        loadSmoothing: 0.6,           // λ_ρ — load EMA smoothing factor
        baseThreshold: 0.5,           // θ_base — baseline root packet threshold
        minThreshold: 0.15,           // θ_min — minimum threshold
        maxThreshold: 0.5,            // θ_max — maximum threshold
    },

    // ─── A4.4 Block Formation Parameters ───────────────────────────────────
    block: {
        minSize: 5,                   // B_min — minimum root packets per block
        maxSize: 20,                  // B_max — maximum root packets per block
        baseSize: 20,                 // B_base — baseline block size
        baseTokenBudget: 100,         // T_base — base token budget per max block
    },

    // ─── Packet Parameters ─────────────────────────────────────────────────
    packet: {
        defaultTTL: 10,               // max hops before packet expiry
        sendInterval: 3000,           // ms between packet sends (simulation speed)
        maxPackets: 70,               // total packets to send in simulation
    },

    // ─── Smart Contract ────────────────────────────────────────────────────
    contract: {
        address: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    },
};

export default ORBIT_CONFIG;
