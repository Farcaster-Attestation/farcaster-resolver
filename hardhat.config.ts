import { config as dotenv } from "dotenv"
import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox-viem";

dotenv()

const accounts = [
  process.env.PRIVATE_KEY!
]

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    hardhat: {
      forking: {
        url: process.env.RPC_URL!,
      },
    },
    optimism: {
      url: process.env.RPC_URL!,
      accounts,
    }
  }
};

export default config;
