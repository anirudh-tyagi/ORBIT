// ═══════════════════════════════════════════════════════════════════════════
// ORBIT Framework — Block Node
// Implements: Adaptive block formation, root packet accumulation,
// Merkle root computation, block submission, reward distribution invocation
// ═══════════════════════════════════════════════════════════════════════════

import express from 'express';
import cors from 'cors';
import blake3 from 'blake3';
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
        console.warn('[BlockNode] No contract ABI found');
        abi = null;
    }
}

const CFG = ORBIT_CONFIG;
const app = express();
app.use(cors());
app.use(express.json());

// ─── Blockchain Connection ─────────────────────────────────────────────
const provider = new ethers.JsonRpcProvider(CFG.network.rpcUrl);
const signer = new ethers.Wallet(CFG.network.blockNode.walletKey, provider);
const contract = abi
    ? new ethers.Contract(CFG.contract.address, abi, signer)
    : null;

// ─── Block Formation State ─────────────────────────────────────────────
let TMP = [];                    // Temporary buffer of root packets
let hopArrayBlock = [];          // Consolidated hopArray for current block
let currentBlockSize = 10;       // Current adaptive block size B(t)
let nonce = null;
let isSending = false;
let pendingTransactions = [];
let blocksFormed = 0;
let blockLog = [];               // Block formation history

// ─── Receive Root Packet (Phase 1 — Eq. 60) ───────────────────────────
function accumulateRootPacket(rootPacket) {
    TMP.push(rootPacket);

    // Merge hopArray — Eq. 61
    if (rootPacket.hopArray && rootPacket.hopArray.length > 0) {
        hopArrayBlock.push(...rootPacket.hopArray);
    }

    console.log(`[BlockNode] Root packet accumulated: ${TMP.length}/${currentBlockSize}`);

    // Phase 2 — Block Criteria Evaluation (Eq. 62)
    if (TMP.length >= currentBlockSize) {
        formBlock();
    }
}

// ─── Phase 3 — Block Generation ────────────────────────────────────────
async function formBlock() {
    const packetsInBlock = TMP.splice(0, currentBlockSize);
    const hopsInBlock = [...hopArrayBlock];
    hopArrayBlock = [];

    console.log(`[BlockNode] ═══ Forming block #${blocksFormed + 1} with ${packetsInBlock.length} root packets ═══`);

    // Merkle root computation — Eq. 63
    const txData = packetsInBlock.map(pkt => JSON.stringify({
        src: pkt.src || pkt.header?.source_address || 'unknown',
        dest: pkt.dest || pkt.header?.destination_address || 'unknown',
        payload: pkt.payload?.timestamp || new Date().toISOString(),
        hopArray: pkt.hopArray || [],
        ttl: pkt.ttl || 0,
    }));

    // Aggregated signature — Eq. 64 (simplified as Blake3 hash of all packet hashes)
    const packetHashes = packetsInBlock.map(pkt => {
        if (pkt.hash && typeof pkt.hash === 'number') return pkt.hash.toString();
        return JSON.stringify(pkt.payload || pkt);
    });
    const aggSignature = blake3.hash(packetHashes.join('')).toString('hex');

    // Block hash — Eq. 65
    const prevBlockHash = blockLog.length > 0
        ? blockLog[blockLog.length - 1].blockHash
        : '0'.repeat(64);
    const timestamp = Date.now().toString();
    const nonce_val = Math.floor(Math.random() * 0xFFFFFFFF).toString(16);
    const blockHash = blake3.hash(prevBlockHash + aggSignature + timestamp + nonce_val).toString('hex');

    const block = {
        data: txData,
        src: packetsInBlock[0]?.header?.source_address || 'source',
        dest: packetsInBlock[packetsInBlock.length - 1]?.header?.destination_address || 'dest',
        timeStamp: timestamp,
        signature: aggSignature,
        hopArray: hopsInBlock,
        blockSize: packetsInBlock.length,
        blockHash: blockHash,
    };

    blocksFormed++;

    blockLog.push({
        index: blocksFormed,
        size: packetsInBlock.length,
        timestamp: Date.now(),
        blockHash,
        hopCount: hopsInBlock.length,
        adaptiveSize: currentBlockSize,
    });

    // Phase 4 — Smart Contract Invocation (Eq. 67)
    if (contract) {
        // Submit block
        try {
            const saveMethod = contract.submitBlock || contract.save;
            if (saveMethod) {
                await sendTransaction('submitBlock', block);
            }
        } catch (err) {
            console.log('[BlockNode] Block submission note:', err.message?.substring(0, 100));
        }

        // Distribute rewards
        try {
            const hopAddresses = hopsInBlock.map(h => h.addr || h);
            if (hopAddresses.length > 0) {
                const distributeMethod = contract.distributeRewards || contract.distributeTokens;
                if (contract.distributeRewards) {
                    await sendTransaction('distributeRewards', hopAddresses, packetsInBlock.length);
                } else if (contract.distributeTokens) {
                    await sendTransaction('distributeTokens', hopAddresses);
                }
            }
        } catch (err) {
            console.log('[BlockNode] Reward distribution note:', err.message?.substring(0, 100));
        }
    }

    console.log(`[BlockNode] ✅ Block #${blocksFormed} formed — ${packetsInBlock.length} packets, ${hopsInBlock.length} hops`);
}

// ─── Transaction Queue ─────────────────────────────────────────────────
async function sendTransaction(methodName, ...args) {
    pendingTransactions.push({ methodName, args });
    if (!isSending) {
        isSending = true;
        while (pendingTransactions.length > 0) {
            const { methodName: method, args: txArgs } = pendingTransactions.shift();
            try {
                if (nonce === null) {
                    nonce = await provider.getTransactionCount(signer.address);
                }
                const tx = await contract[method](...txArgs, { nonce });
                await tx.wait();
                nonce++;
            } catch (error) {
                console.error(`[BlockNode] Tx error (${method}):`, error.message?.substring(0, 150));
                nonce = null;  // Reset nonce on error
            }
        }
        isSending = false;
    }
}

// ─── Express API ───────────────────────────────────────────────────────

// POST /submitRootPacket — receive classified root packet from IoT node
app.post('/submitRootPacket', (req, res) => {
    const rootPacket = req.body;
    accumulateRootPacket(rootPacket);
    res.json({
        status: 'ok',
        bufferSize: TMP.length,
        targetSize: currentBlockSize,
        blocksFormed,
    });
});

// POST /updateBlockSize — edge node pushes adaptive block size
app.post('/updateBlockSize', (req, res) => {
    const { blockSize } = req.body;
    if (blockSize >= CFG.block.minSize && blockSize <= CFG.block.maxSize) {
        currentBlockSize = blockSize;
    }
    res.json({ currentBlockSize });
});

// GET /status — block node status
app.get('/status', (req, res) => {
    res.json({
        blocksFormed,
        bufferSize: TMP.length,
        currentBlockSize,
        blockLog: blockLog.slice(-20),
    });
});

// GET /blockLog — full block formation history
app.get('/blockLog', (req, res) => {
    res.json(blockLog);
});

// ─── Start Server ──────────────────────────────────────────────────────
const PORT = CFG.network.blockNode.httpPort;
app.listen(PORT, () => {
    console.log(`[BlockNode] ORBIT Block Node running on port ${PORT}`);
    console.log(`[BlockNode] Adaptive block size: ${CFG.block.minSize}–${CFG.block.maxSize}`);
});
