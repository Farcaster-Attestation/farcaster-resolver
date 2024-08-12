import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"

const FarcasterOptimisticVerifierModule = buildModule("FarcasterOptimisticVerifierModule", (m) => {
  const admin = m.getAccount(0)

  const resolver = m.contractAt("FarcasterResolver", "0xba8BfD8306A6a588302A6B931fa53fb6eb8E3292")
  const walletOnchainVerifier = m.contractAt("FarcasterWalletOnchainVerifier", "0xfa22641E041828a15CE6d1c29188B3D2d29CE2D5")

  const walletOptimisticVerifier = m.contract("FarcasterWalletOptimisticVerifier", [walletOnchainVerifier, admin], {})
  
  m.call(resolver, "setVerifier", [2, walletOptimisticVerifier], { id: "setWalletOptimisticVerifier" })

  return { resolver, walletOptimisticVerifier };
});

export default FarcasterOptimisticVerifierModule;