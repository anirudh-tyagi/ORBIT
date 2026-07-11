require("@nomicfoundation/hardhat-toolbox");
module.exports = {
  solidity: "0.8.17",
  networks: {
    hardhat: {
      chainId: 31337,
      accounts: {
        count: 10,       // 5 IoT + 1 Edge + 1 Block + 1 Coordinator + 2 spare
        mnemonic: "test test test test test test test test test test test junk",
        accountsBalance: "10000000000000000000000",  // 10000 ETH each
      },
    },
  },
};
