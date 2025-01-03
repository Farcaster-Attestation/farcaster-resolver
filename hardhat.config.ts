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
  ignition: {
    strategyConfig: {
      create2: {
        // To learn more about salts, see the CreateX documentation
        salt: "0x0000000000000000000000000000000000000000000000000000000000000000",
      },
    },
  },
  mocha: {
    timeout: 400000
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
    supersim_op: {
      url: 'http://127.0.0.1:9545',
      accounts: ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'], // test junk
    },
    supersim_base: {
      url: 'http://127.0.0.1:9546',
      accounts: ['0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'], // test junk
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
