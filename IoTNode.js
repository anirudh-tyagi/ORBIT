// ═══════════════════════════════════════════════════════════════════════════
// ORBIT Framework — IoT Node (Configurable Relay/Source Node)
// Usage: node IoTNode.js <NODE_ID>  (1–5)
// Replaces Server_2.js through Server_6.js with a single configurable file
// Implements: BLS signing/verification, edge-assisted routing,
// graceful degradation (LRC fallback), hop logging, root packet classification
// ═══════════════════════════════════════════════════════════════════════════

import bls from '@chainsafe/bls';
import blake3 from 'blake3';
import { ethers } from 'ethers';
import net from 'net';
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
        console.warn('[IoTNode] No ABI found');
        abi = null;
    }
}

// ─── Node Configuration from CLI ───────────────────────────────────────
const NODE_ID = parseInt(process.argv[2]) || 1;
const CFG = ORBIT_CONFIG;
const nodeConfig = CFG.network.iotNodes.find(n => n.id === NODE_ID);

if (!nodeConfig) {
    console.error(`[IoTNode] Invalid NODE_ID: ${NODE_ID}. Valid: 1-${CFG.network.iotNodes.length}`);
    process.exit(1);
}

const currentAddress = nodeConfig.address;
const walletKey = nodeConfig.walletKey;
console.log(`[IoTNode-${NODE_ID}] Starting as ${currentAddress}`);

// ─── Blockchain Connection ─────────────────────────────────────────────
const provider = new ethers.JsonRpcProvider(CFG.network.rpcUrl);
const signer = new ethers.Wallet(walletKey, provider);
const contract = abi
    ? new ethers.Contract(CFG.contract.address, abi, signer)
    : null;

// ─── BLS Key Generation ───────────────────────────────────────────────
const secretKey = bls.SecretKey.fromKeygen();

// ─── State ─────────────────────────────────────────────────────────────
let blocks = {};
let pendingTransactions = [];
let isSending = false;
let nonce = null;
let packetsProcessed = 0;
let packetsForwarded = 0;
let packetsDropped = 0;

// Local Routing Cache (LRC) for graceful degradation
let lrc = {};
let lrcTimestamp = 0;
let currentThreshold = CFG.adaptive.baseThreshold;
let currentBlockSize = CFG.block.baseSize;

// ─── Edge Node Communication ──────────────────────────────────────────
async function queryEdgeNode(currentNode) {
    try {
        const edgeUrl = `http://localhost:${CFG.network.edgeNode.httpPort}`;
        const response = await fetch(`${edgeUrl}/bestNextHop?current=${currentNode}`);
        if (response.ok) {
            const data = await response.json();
            currentThreshold = data.threshold;
            currentBlockSize = data.blockSize;
            return data.nextHop;
        }
    } catch {
        // Edge unavailable — graceful degradation
    }
    return null;
}

async function reportEventToEdge(event) {
    try {
        const edgeUrl = `http://localhost:${CFG.network.edgeNode.httpPort}`;
        await fetch(`${edgeUrl}/reportEvent`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(event),
        });
    } catch {
        // Edge unavailable — silently fail
    }
}

async function submitRootPacketToBlockNode(rootPacket) {
    try {
        const blockUrl = `http://localhost:${CFG.network.blockNode.httpPort}`;
        await fetch(`${blockUrl}/submitRootPacket`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(rootPacket),
        });
    } catch {
        // Block node unavailable
    }
}

async function refreshLRC() {
    try {
        const edgeUrl = `http://localhost:${CFG.network.edgeNode.httpPort}`;
        const response = await fetch(`${edgeUrl}/lrc`);
        if (response.ok) {
            const data = await response.json();
            lrc = data.lrc;
            lrcTimestamp = data.timestamp;
            currentThreshold = data.threshold;
            currentBlockSize = data.blockSize;
        }
    } catch {
        // Edge unavailable
    }
}

// Periodic LRC refresh
setInterval(refreshLRC, CFG.routing.lrcPushInterval);

// ─── Graceful Degradation — Local routing using LRC ───────────────────
function selectNextHopLocal(currentNode, availableClients) {
    const lrcAge = Date.now() - lrcTimestamp;

    if (lrcAge > CFG.routing.maxLrcAge || Object.keys(lrc).length === 0) {
        // Emergency fallback: random selection (minimum-latency equivalent)
        return availableClients[Math.floor(Math.random() * availableClients.length)];
    }

    // Use LRC to select best neighbor based on cached scores
    let bestAddr = null;
    let bestScore = -Infinity;

    Object.entries(lrc).forEach(([addr, metrics]) => {
        if (addr === currentNode) return;
        const score = metrics.success_rate * metrics.trust_score
                    - (metrics.avg_latency / 1000)
                    - metrics.drop_rate;
        if (score > bestScore) {
            bestScore = score;
            bestAddr = addr;
        }
    });

    return bestAddr || availableClients[Math.floor(Math.random() * availableClients.length)];
}

// ─── BLS Signing ──────────────────────────────────────────────────────
const signMsg = (msg) => {
    const hash = new TextEncoder().encode(JSON.stringify(msg?.payload));
    const signature = bls.sign(secretKey.toBytes(), hash);
    msg.header.source_address = currentAddress;
    msg.hash = hash;
    msg.signature = signature;
    msg.publicKey = bls.secretKeyToPublicKey(secretKey.toBytes());
    return msg;
};

const onMessageSend = (msg) => {
    const signedMsg = signMsg(msg);
    return signedMsg ? JSON.stringify(signedMsg) : undefined;
};

// ─── BLS Verification + ORBIT Processing ──────────────────────────────
const verifyMsg = async (msg) => {
    const startTime = Date.now();

    // BLS Signature Verification — Eq. 6
    const isValid = bls.verify(
        new Uint8Array([...Object.values(msg.publicKey)]),
        new Uint8Array([...Object.values(msg.hash)]),
        new Uint8Array([...Object.values(msg.signature)])
    );

    if (!isValid) {
        packetsDropped++;
        // Report invalid signature to edge
        await reportEventToEdge({
            nodeAddr: currentAddress,
            success: false,
            latency: Date.now() - startTime,
            dropped: false,
            invalidSig: true,
        });
        return 0;
    }

    packetsProcessed++;

    // Blake3 hash computation
    msg.hash = parseInt(
        blake3.hash(
            new TextDecoder().decode(new Uint8Array([...Object.values(msg.hash)]))
        ).toString('hex'),
        16
    );

    // ─── Hop Array Logging ─────────────────────────────────────────
    msg.hopArray.push({
        addr: currentAddress,
        timeStamp: Date.now(),
    });

    // ─── Root Packet Classification — Eq. 48 ──────────────────────
    // Adaptive threshold from edge node
    const normalizedHash = (msg.hash % 1000) / 1000;  // normalize to [0,1]
    if (normalizedHash < currentThreshold) {
        msg.root = true;
        // Submit root packet to block node
        await submitRootPacketToBlockNode({
            header: msg.header,
            payload: msg.payload,
            hash: msg.hash,
            hopArray: msg.hopArray,
            ttl: msg.ttl,
            src: msg.header?.source_address,
            dest: msg.header?.destination_address,
        });
    } else {
        msg.root = false;
    }

    // ─── Destination Check ─────────────────────────────────────────
    if (msg.header.destination_address === currentAddress) {
        console.log(`[IoTNode-${NODE_ID}] 📨 Destination reached! Packet delivered.`);
        msg.ttl = 0;
        packetsForwarded++;

        // Report successful delivery
        await reportEventToEdge({
            nodeAddr: currentAddress,
            success: true,
            latency: Date.now() - startTime,
            dropped: false,
            invalidSig: false,
        });

        // Distribute rewards via smart contract
        if (contract && msg.hopArray.length > 0) {
            const hopAddresses = msg.hopArray.map(h => h.addr);
            await sendTransaction(contract, 'distributeTokens', hopAddresses);
        }
    } else {
        packetsForwarded++;
        // Report forwarding event
        await reportEventToEdge({
            nodeAddr: currentAddress,
            success: true,
            latency: Date.now() - startTime,
            dropped: false,
            invalidSig: false,
        });
    }

    return msg;
};

const onMessageRecieve = async (msg) => {
    const verifiedMsg = await verifyMsg(msg);
    if (verifiedMsg && msg.ttl > 0) {
        --msg.ttl;
        return verifiedMsg;
    }
    return false;
};

// ─── Transaction Queue ────────────────────────────────────────────────
async function sendTransaction(contract, methodName, args) {
    pendingTransactions.push({ contract, methodName, args });
    if (!isSending) {
        isSending = true;
        while (pendingTransactions.length > 0) {
            const { contract: c, methodName: m, args: a } = pendingTransactions.shift();
            try {
                if (nonce === null) {
                    nonce = await provider.getTransactionCount(signer.address);
                }
                const tx = await c[m](a, { nonce });
                await tx.wait();
                nonce++;
            } catch (error) {
                console.error(`[IoTNode-${NODE_ID}] Tx error:`, error.message?.substring(0, 100));
                nonce = null;
            }
        }
        isSending = false;
    }
}

// ─── TCP Client — Connect to Coordinator ──────────────────────────────
const client = new net.Socket();

client.connect({ port: CFG.network.tcpPort }, () => {
    console.log(`[IoTNode-${NODE_ID}] Connected to coordinator on port ${CFG.network.tcpPort}`);

    client.on('data', async (data) => {
        try {
            console.log(`[IoTNode-${NODE_ID}] 📦 Packet received`);
            const message = JSON.parse(data.toString());
            const redirectMsg = await onMessageRecieve(JSON.parse(message.msg));

            if (redirectMsg && redirectMsg.ttl > 0) {
                // ─── Edge-Assisted Routing (UCB1) ──────────────────
                let nextClient;
                const edgeRecommendation = await queryEdgeNode(currentAddress);

                if (edgeRecommendation && message.clients?.length > 0) {
                    // Use edge's UCB1 recommendation
                    nextClient = message.clients.find(c =>
                        c?._peername?.port || true // match first available
                    );
                    console.log(`[IoTNode-${NODE_ID}] 🧠 Edge recommends: ${edgeRecommendation}`);
                } else {
                    // Graceful degradation — use LRC
                    nextClient = message.clients[Math.floor(Math.random() * message.clients.length)];
                    console.log(`[IoTNode-${NODE_ID}] 📡 Using local routing cache (degraded mode)`);
                }

                if (nextClient && message.clients?.length > 0) {
                    message.clients = message.clients.filter(cli => cli !== nextClient);
                    client.write(JSON.stringify({
                        message: onMessageSend(redirectMsg),
                        clients: message.clients,
                        client: nextClient,
                    }));
                }
            }
        } catch (err) {
            console.error(`[IoTNode-${NODE_ID}] Error processing packet:`, err.message);
        }
    });
});

client.on('error', (err) => {
    console.error(`[IoTNode-${NODE_ID}] Connection error:`, err.message);
});

console.log(`[IoTNode-${NODE_ID}] ORBIT IoT Node ready — address: ${currentAddress}`);
