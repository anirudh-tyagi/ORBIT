// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// ═══════════════════════════════════════════════════════════════════════════
// ORBIT Smart Contract — Performance-Based Reward System
// Implements: Node registration, NMT snapshots, adaptive block submission,
// performance-based token distribution, malicious node flagging, trust recovery
// ═══════════════════════════════════════════════════════════════════════════

struct HopInfo {
    string addr;
    uint256 timeStamp;
}

struct Block {
    string[] data;
    string src;
    string dest;
    string timeStamp;
    string signature;
    HopInfo[] hopArray;
    uint256 blockSize;      // adaptive block size at time of creation
}

struct NodeMetrics {
    string addr;
    uint256 successRate;    // scaled by 1000 (e.g., 950 = 0.950)
    uint256 avgLatency;     // in ms
    uint256 dropRate;       // scaled by 1000
    uint256 trustScore;     // scaled by 1000 (e.g., 800 = 0.800)
    uint256 packetsForwarded;
    uint256 lastUpdated;
    bool isMalicious;
    bool isRegistered;
}

struct TokenInfo {
    string addr;
    uint256 balance;
}

contract ORBIT {

    // ─── State Variables ───────────────────────────────────────────────────
    uint256 public successRate = 0;
    uint256 public totalPacketsGenerated = 0;

    TokenInfo[] public allTokens;
    Block[] public allBlocks;

    mapping(string => NodeMetrics) public nodeMetrics;
    mapping(string => uint256) public tokenBalances;
    string[] public registeredNodes;

    // Reward weight configuration (scaled by 100)
    uint256 public weightForwarding = 35;   // a = 0.35
    uint256 public weightSuccess = 30;      // b = 0.30
    uint256 public weightDelay = 15;        // c = 0.15
    uint256 public weightTrust = 20;        // e = 0.20

    // Block formation bounds
    uint256 public minBlockSize = 5;
    uint256 public maxBlockSize = 20;
    uint256 public baseTokenBudget = 100;

    // ─── Events ────────────────────────────────────────────────────────────
    event NodeRegistered(string addr, uint256 initialTrust);
    event BlockSubmitted(uint256 blockIndex, uint256 blockSize, uint256 timestamp);
    event RewardsDistributed(uint256 blockIndex, uint256 totalTokens);
    event NodeFlaggedMalicious(string addr, uint256 trustScore);
    event TrustRecovered(string addr, uint256 newTrustScore);
    event TokensAwarded(string addr, uint256 amount, uint256 rewardScore);
    event MetricsUpdated(string addr, uint256 successRate, uint256 trustScore);

    // ─── Node Registration ─────────────────────────────────────────────────
    function registerNode(string memory addr) public {
        require(!nodeMetrics[addr].isRegistered, "Node already registered");

        nodeMetrics[addr] = NodeMetrics({
            addr: addr,
            successRate: 800,       // initial 0.800
            avgLatency: 100,        // initial 100ms
            dropRate: 0,
            trustScore: 800,        // initial 0.800
            packetsForwarded: 0,
            lastUpdated: block.timestamp,
            isMalicious: false,
            isRegistered: true
        });

        registeredNodes.push(addr);
        emit NodeRegistered(addr, 800);
    }

    // ─── NMT Update (called by Edge Node) ──────────────────────────────────
    function updateNMT(
        string memory addr,
        uint256 _successRate,
        uint256 _avgLatency,
        uint256 _dropRate,
        uint256 _trustScore,
        uint256 _packetsForwarded
    ) public {
        require(nodeMetrics[addr].isRegistered, "Node not registered");
        require(!nodeMetrics[addr].isMalicious, "Node is flagged malicious");

        nodeMetrics[addr].successRate = _successRate;
        nodeMetrics[addr].avgLatency = _avgLatency;
        nodeMetrics[addr].dropRate = _dropRate;
        nodeMetrics[addr].trustScore = _trustScore;
        nodeMetrics[addr].packetsForwarded = _packetsForwarded;
        nodeMetrics[addr].lastUpdated = block.timestamp;

        emit MetricsUpdated(addr, _successRate, _trustScore);
    }

    // ─── Block Submission (adaptive size 5-20) ─────────────────────────────
    function submitBlock(Block memory blk) public {
        require(
            blk.data.length >= minBlockSize && blk.data.length <= maxBlockSize,
            "Block size outside adaptive bounds [5,20]"
        );

        Block storage newBlock = allBlocks.push();
        for (uint256 i = 0; i < blk.data.length; i++) {
            newBlock.data.push(blk.data[i]);
        }
        newBlock.src = blk.src;
        newBlock.dest = blk.dest;
        newBlock.timeStamp = blk.timeStamp;
        newBlock.signature = blk.signature;
        newBlock.blockSize = blk.data.length;

        for (uint256 i = 0; i < blk.hopArray.length; i++) {
            newBlock.hopArray.push(blk.hopArray[i]);
        }

        emit BlockSubmitted(allBlocks.length - 1, blk.data.length, block.timestamp);
    }

    // ─── Performance-Based Reward Distribution ─────────────────────────────
    // Q_j = a·F_j + b·R_j − c·d̄_j + e·T_j
    // tokens_j = T_block · max(0, Q_j) / Σ max(0, Q_k)
    function distributeRewards(
        string[] memory hopArray,
        uint256 currentBlockSize
    ) public {
        require(hopArray.length > 0, "Empty hopArray");

        successRate++;

        // Compute adaptive token budget: T_block = T_base * B(t) / B_max
        uint256 tokenBudget = (baseTokenBudget * currentBlockSize) / maxBlockSize;
        if (tokenBudget == 0) tokenBudget = 1;

        // Count unique nodes and their forwarding frequency
        string[] memory uniqueNodes = new string[](hopArray.length);
        uint256[] memory forwardCounts = new uint256[](hopArray.length);
        uint256 uniqueCount = 0;

        for (uint256 i = 0; i < hopArray.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < uniqueCount; j++) {
                if (keccak256(abi.encodePacked(uniqueNodes[j])) ==
                    keccak256(abi.encodePacked(hopArray[i]))) {
                    forwardCounts[j]++;
                    found = true;
                    break;
                }
            }
            if (!found) {
                uniqueNodes[uniqueCount] = hopArray[i];
                forwardCounts[uniqueCount] = 1;
                uniqueCount++;
            }
        }

        // Compute reward scores Q_j for each unique node
        uint256[] memory rewardScores = new uint256[](uniqueCount);
        uint256 totalRewardScore = 0;

        // Compute network-wide mean latency for normalization
        uint256 totalLatency = 0;
        uint256 activeCount = 0;
        for (uint256 i = 0; i < uniqueCount; i++) {
            if (nodeMetrics[uniqueNodes[i]].isRegistered) {
                totalLatency += nodeMetrics[uniqueNodes[i]].avgLatency;
                activeCount++;
            }
        }
        uint256 meanLatency = activeCount > 0 ? totalLatency / activeCount : 100;
        if (meanLatency == 0) meanLatency = 1;

        for (uint256 i = 0; i < uniqueCount; i++) {
            string memory nodeAddr = uniqueNodes[i];

            // F_j = forwardCount / totalHops (scaled by 1000)
            uint256 Fj = (forwardCounts[i] * 1000) / hopArray.length;

            // R_j from NMT (already scaled by 1000)
            uint256 Rj = nodeMetrics[nodeAddr].isRegistered
                ? nodeMetrics[nodeAddr].successRate
                : 500;

            // d̄_j = L_j / L̄ (scaled by 1000)
            uint256 dj = nodeMetrics[nodeAddr].isRegistered
                ? (nodeMetrics[nodeAddr].avgLatency * 1000) / meanLatency
                : 1000;

            // T_j from NMT (already scaled by 1000)
            uint256 Tj = nodeMetrics[nodeAddr].isRegistered
                ? nodeMetrics[nodeAddr].trustScore
                : 500;

            // Q_j = a·F_j + b·R_j − c·d̄_j + e·T_j (all scaled)
            uint256 positive = (weightForwarding * Fj + weightSuccess * Rj + weightTrust * Tj) / 100;
            uint256 negative = (weightDelay * dj) / 100;

            // max(0, Q_j)
            if (positive > negative) {
                rewardScores[i] = positive - negative;
            } else {
                rewardScores[i] = 0;
            }

            totalRewardScore += rewardScores[i];
        }

        // Distribute tokens proportionally
        if (totalRewardScore > 0) {
            for (uint256 i = 0; i < uniqueCount; i++) {
                if (rewardScores[i] > 0) {
                    uint256 tokens = (tokenBudget * rewardScores[i]) / totalRewardScore;
                    if (tokens == 0) tokens = 1;

                    // Update token balance
                    string memory addr = uniqueNodes[i];
                    bool tokenFound = false;
                    for (uint256 j = 0; j < allTokens.length; j++) {
                        if (keccak256(abi.encodePacked(allTokens[j].addr)) ==
                            keccak256(abi.encodePacked(addr))) {
                            allTokens[j].balance += tokens;
                            tokenFound = true;
                            emit TokensAwarded(addr, tokens, rewardScores[i]);
                            break;
                        }
                    }
                    if (!tokenFound) {
                        allTokens.push(TokenInfo(addr, tokens));
                        emit TokensAwarded(addr, tokens, rewardScores[i]);
                    }
                }
            }
        }

        emit RewardsDistributed(allBlocks.length > 0 ? allBlocks.length - 1 : 0, tokenBudget);
    }

    // ─── Flag Malicious Node ───────────────────────────────────────────────
    function flagMalicious(string memory addr) public {
        require(nodeMetrics[addr].isRegistered, "Node not registered");
        nodeMetrics[addr].isMalicious = true;
        nodeMetrics[addr].trustScore = 0;
        emit NodeFlaggedMalicious(addr, 0);
    }

    // ─── Trust Recovery ────────────────────────────────────────────────────
    function recoverTrust(string memory addr, uint256 newTrustScore) public {
        require(nodeMetrics[addr].isRegistered, "Node not registered");
        require(nodeMetrics[addr].isMalicious == false, "Cannot recover flagged node");
        require(newTrustScore <= 1000, "Trust score exceeds max");
        nodeMetrics[addr].trustScore = newTrustScore;
        emit TrustRecovered(addr, newTrustScore);
    }

    // ─── Legacy compatibility for old distributeTokens calls ───────────────
    function distributeTokens(string[] memory hopArray) public {
        distributeRewards(hopArray, 10);
    }

    // ─── Increment success rate ────────────────────────────────────────────
    function increaseRate() public {
        successRate++;
    }

    // ─── View Functions ────────────────────────────────────────────────────
    function getRate() public view returns (uint256) {
        return successRate;
    }

    function getAllToken() public view returns (TokenInfo[] memory) {
        return allTokens;
    }

    function getAllBlocks() public view returns (Block[] memory) {
        return allBlocks;
    }

    function getNodeMetricsData(string memory addr) public view returns (NodeMetrics memory) {
        return nodeMetrics[addr];
    }

    function getRegisteredNodes() public view returns (string[] memory) {
        return registeredNodes;
    }

    function getRegisteredNodeCount() public view returns (uint256) {
        return registeredNodes.length;
    }

    function getBlockCount() public view returns (uint256) {
        return allBlocks.length;
    }
}
