const hre = require("hardhat");

async function main() {
  console.log("═══ ORBIT Smart Contract Deployment ═══\n");

  // Deploy ORBIT contract
  let contract;
  try {
    contract = await hre.ethers.deployContract("ORBIT");
    await contract.waitForDeployment();
    console.log(`[Deploy] ✅ ORBIT contract deployed at: ${contract.target}\n`);
  } catch (err) {
    // Fallback to BPRSec if ORBIT contract not compiled yet
    console.log("[Deploy] ORBIT.sol not found, trying BPRSec.sol...");
    contract = await hre.ethers.deployContract("BPRSec");
    await contract.waitForDeployment();
    console.log(`[Deploy] ✅ BPRSec contract deployed at: ${contract.target}\n`);
  }

  // Register IoT nodes
  const nodes = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"];

  if (contract.registerNode) {
    console.log("[Deploy] Registering IoT nodes...");
    for (const addr of nodes) {
      try {
        const tx = await contract.registerNode(addr);
        await tx.wait();
        console.log(`  ✅ Registered ${addr}`);
      } catch (err) {
        console.log(`  ℹ ${addr} — ${err.message?.substring(0, 60)}`);
      }
    }
  }

  console.log("\n═══ Deployment Complete ═══");
  console.log(`Contract Address: ${contract.target}`);
  console.log("Update this address in orbit.config.js if different from default.\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});