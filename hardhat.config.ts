import { config as dotenv } from "dotenv"
import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";

dotenv()

const accounts = [
  process.env.PRIVATE_KEY!
]

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.26",
    settings: {
      optimizer: {
        enabled: true,
        runs: 100000,
      },
    },
  },
  networks: {
    hardhat: {
      forking: {
        url: process.env.RPC_URL!,
        blockNumber: 128418800,
      },
    },
    optimism: {
      url: process.env.RPC_URL!,
      accounts,
    },
    optimism_sepolia: {
      url: process.env.RPC_TESTNET_URL!,
      accounts,
    },
  },
  etherscan: {
    apiKey: {
      optimismSepolia: process.env.ETHERSCAN_API_KEY!,
      optimisticEthereum: process.env.ETHERSCAN_API_KEY!,
    },
    customChains: [
      {
        network: "optimismSepolia",
        chainId: 11155420,
        urls: {
            apiURL: "https://api-sepolia-optimism.etherscan.io/api",
            browserURL: "https://sepolia-optimism.etherscan.io"
        }
      },
    ]
  },
};

export default config;
