// ═══════════════════════════════════════════════════════════════════════════
// ORBIT Framework — Coordinator Server (Source Node + API)
// Manages TCP connections to IoT nodes, dispatches packets with BLS,
// provides Express API endpoints for the dashboard
// ═══════════════════════════════════════════════════════════════════════════

import bls from '@chainsafe/bls';
import blake3 from 'blake3';
import { ethers } from 'ethers';
import express from 'express';
import net from 'net';
import { createRequire } from 'module';
import * as fs from 'fs';
import ORBIT_CONFIG from './orbit.config.js';

const require = createRequire(import.meta.url);
let abi;
try {
    abi = require('./artifacts/contracts/ORBIT.sol/ORBIT.json').abi;
} catch {
    try {
        abi = require('./artifacts/contracts/BPRSec.sol/BPRSec.json').abi;
    } catch {
        console.warn('[Server] No contract ABI found');
        abi = null;
    }
}

const CFG = ORBIT_CONFIG;
const expressServer = express();
import cors from 'cors';
expressServer.use(cors());
expressServer.use(express.json());

// ─── Blockchain Connection ─────────────────────────────────────────────
const provider = new ethers.JsonRpcProvider(CFG.network.rpcUrl);
const signer = new ethers.Wallet(CFG.network.coordinatorWalletKey, provider);
const contract = abi
    ? new ethers.Contract(CFG.contract.address, abi, signer)
    : null;

// ─── BLS Key ──────────────────────────────────────────────────────────
const secretKey = bls.SecretKey.fromKeygen();

// ─── State ─────────────────────────────────────────────────────────────
let clients = [];
let count = 0;
let packetsSent = 0;
let startTime = Date.now();
const REQUIRED_CLIENTS = CFG.network.iotNodes.length;

// ─── TCP Server ────────────────────────────────────────────────────────
const tcpServer = net.createServer((socket) => {
    console.log(`[Server] IoT node connected from port ${socket.remotePort}`);
    clients.push(socket);
    ++count;

    if (count === REQUIRED_CLIENTS) {
        console.log(`[Server] ═══ All ${REQUIRED_CLIENTS} IoT nodes connected — Starting ORBIT protocol ═══`);
        startTime = Date.now();

        // Notify edge node that simulation is starting
        notifyEdge('/packetGenerated', {});
        startTransferring();
    }

    socket.on('data', (data) => {
        try {
            const msg = JSON.parse(data.toString());
            const nextClient = clients.find(
                client => client._peername?.port === msg.client?._peername?.port
            );
            if (nextClient) {
                nextClient.write(JSON.stringify({ msg: msg.message, clients: msg.clients }));
            }
        } catch (err) {
            console.error('[Server] Data parse error:', err.message);
        }
    });

    socket.on('error', (err) => {
        console.error('[Server] Socket error:', err.message);
    });
});

// ─── Packet Dispatch ──────────────────────────────────────────────────
const startTransferring = () => {
    let i = 0;
    fs.readFile('./iot_data.json', 'utf8', (err, data) => {
        if (err) {
            console.error('[Server] Error reading iot_data.json:', err);
            return;
        }

        const jsonData = JSON.parse(data);
        const maxPackets = Math.min(jsonData.length - 2, CFG.packet.maxPackets);

        const interval = setInterval(() => {
            ++i;
            try {
                const port = Math.floor(Math.random() * clients.length);
                console.log(`[Server] 📤 Sending packet ${i}/${maxPackets}`);
                const signedPacket = onMessageSend(jsonData[i]);
                clients[port].write(JSON.stringify({
                    msg: signedPacket,
                    clients: clients.filter(client => client !== clients[port]),
                }));
                packetsSent++;

                // Notify edge about packet generation
                notifyEdge('/packetGenerated', {});
            } catch (error) {
                console.log('[Server] ❌ Packet dropped:', error.message);
            }

            if (i >= maxPackets) {
                console.log(`[Server] ✅ Successfully sent ${i} packets`);
                clearInterval(interval);
            }
        }, CFG.packet.sendInterval);
    });
};

// ─── BLS Signing ──────────────────────────────────────────────────────
const onMessageSend = (msg) => {
    const signedMsg = signMsg(msg);
    return signedMsg ? JSON.stringify(signedMsg) : undefined;
};

const signMsg = (msg) => {
    const hash = new TextEncoder().encode(JSON.stringify(msg?.payload));
    const signature = bls.sign(secretKey.toBytes(), hash);
    msg.hash = hash;
    msg.signature = signature;
    msg.publicKey = bls.secretKeyToPublicKey(secretKey.toBytes());
    msg.hopArray = [];
    msg.ttl = CFG.packet.defaultTTL;
    return msg;
};

// ─── Edge Node Helper ─────────────────────────────────────────────────
async function notifyEdge(path, body) {
    try {
        await fetch(`http://localhost:${CFG.network.edgeNode.httpPort}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
    } catch {
        // Edge may not be running
    }
}

async function fetchFromEdge(path) {
    try {
        const res = await fetch(`http://localhost:${CFG.network.edgeNode.httpPort}${path}`);
        if (res.ok) return await res.json();
    } catch { /* Edge unavailable */ }
    return null;
}

async function fetchFromBlockNode(path) {
    try {
        const res = await fetch(`http://localhost:${CFG.network.blockNode.httpPort}${path}`);
        if (res.ok) return await res.json();
    } catch { /* Block node unavailable */ }
    return null;
}

// ═══════════════════════════════════════════════════════════════════════════
// Express API Endpoints (for Dashboard)
// ═══════════════════════════════════════════════════════════════════════════

// GET /getBlocks — blockchain blocks (from contract or block node)
expressServer.get('/getBlocks', async (req, res) => {
    try {
        if (contract && contract.getAllBlocks) {
            const data = await contract.getAllBlocks();
            const formatted = data.map(node => ({
                tx: node.data,
                src: node.src,
                dest: node.dest,
                timestamp: node.timeStamp,
                signature: node.signature,
                blockSize: node.blockSize?.toString() || '10',
                hopArray: node.hopArray.map(hop => ({
                    addr: hop.addr,
                    timeStamp: hop.timeStamp.toString(),
                })),
            }));
            return res.json(formatted);
        } else if (contract && contract.getAllNodes) {
            // Fallback to old contract method
            const data = await contract.getAllNodes();
            const formatted = data.map(node => ({
                tx: node.data,
                src: node.src,
                dest: node.dest,
                timestamp: node.timeStamp,
                signature: node.signature,
                hopArray: node.hopArray.map(hop => ({
                    addr: hop.addr,
                    timeStamp: hop.timeStamp.toString(),
                })),
            }));
            return res.json(formatted);
        }
    } catch (err) {
        console.error('[Server] getBlocks error:', err.message);
    }
    res.json([]);
});

// GET /getTokens — token distribution per node
expressServer.get('/getTokens', async (req, res) => {
    try {
        if (contract) {
            const data = await contract.getAllToken();
            return res.json(
                data.map(([address, amount]) => [address, amount.toString()])
            );
        }
    } catch (err) {
        console.error('[Server] getTokens error:', err.message);
    }
    res.json([]);
});

// GET /getRate — successful delivery count
expressServer.get('/getRate', async (req, res) => {
    try {
        if (contract) {
            const data = await contract.getRate();
            return res.json(data.toString());
        }
    } catch (err) {
        console.error('[Server] getRate error:', err.message);
    }
    res.json('0');
});

// GET /getNodeMetrics — NMT data from edge node
expressServer.get('/getNodeMetrics', async (req, res) => {
    const nmt = await fetchFromEdge('/nmt');
    res.json(nmt || {});
});

// GET /getTrustScores — trust score evolution
expressServer.get('/getTrustScores', async (req, res) => {
    const history = await fetchFromEdge('/trustHistory');
    res.json(history || {});
});

// GET /getAnomalies — detected anomalies
expressServer.get('/getAnomalies', async (req, res) => {
    const anomalies = await fetchFromEdge('/anomalies');
    res.json(anomalies || []);
});

// GET /getNetworkLoad — adaptive threshold and network load
expressServer.get('/getNetworkLoad', async (req, res) => {
    const load = await fetchFromEdge('/networkLoad');
    res.json(load || { current: { rho: 0, theta: 0.5, blockSize: 10 }, history: [] });
});

// GET /getRoutingScores — per-node routing scores
expressServer.get('/getRoutingScores', async (req, res) => {
    const scores = await fetchFromEdge('/routingScores');
    res.json(scores || {});
});

// GET /getBlockLog — block formation history from block node
expressServer.get('/getBlockLog', async (req, res) => {
    const log = await fetchFromBlockNode('/blockLog');
    res.json(log || []);
});

// GET /getBlockNodeStatus — block node status
expressServer.get('/getBlockNodeStatus', async (req, res) => {
    const status = await fetchFromBlockNode('/status');
    res.json(status || { blocksFormed: 0, bufferSize: 0, currentBlockSize: 10 });
});

// GET /getSimulationStatus — overall simulation status
expressServer.get('/getSimulationStatus', async (req, res) => {
    res.json({
        connectedNodes: count,
        requiredNodes: REQUIRED_CLIENTS,
        packetsSent,
        uptimeMs: Date.now() - startTime,
        config: {
            iotNodes: CFG.network.iotNodes.length,
            edgePort: CFG.network.edgeNode.httpPort,
            blockPort: CFG.network.blockNode.httpPort,
            sendInterval: CFG.packet.sendInterval,
            maxPackets: CFG.packet.maxPackets,
            ttl: CFG.packet.defaultTTL,
        },
    });
});

// GET /getConfig — ORBIT configuration parameters
expressServer.get('/getConfig', (req, res) => {
    res.json({
        routing: CFG.routing,
        anomaly: CFG.anomaly,
        trust: CFG.trust,
        adaptive: CFG.adaptive,
        block: CFG.block,
    });
});

// ─── Start Servers ─────────────────────────────────────────────────────
tcpServer.listen(CFG.network.tcpPort, () => {
    console.log(`[Server] ═══ ORBIT Coordinator ═══`);
    console.log(`[Server] TCP server on port ${CFG.network.tcpPort}`);
    console.log(`[Server] Waiting for ${REQUIRED_CLIENTS} IoT nodes...`);
});

expressServer.listen(CFG.network.expressPort, () => {
    console.log(`[Server] Dashboard API on port ${CFG.network.expressPort}`);
});
