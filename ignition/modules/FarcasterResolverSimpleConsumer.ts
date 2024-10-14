import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"

const FarcasterMembershipModule = buildModule("FarcasterMembershipModule", (m) => {
  // const { resolver, eas } = m.useModule(FarcasterResolverModule)

  const eas = m.contractAt("EAS", "0x4200000000000000000000000000000000000021");
  const resolver = m.contractAt("FarcasterResolver", "0xba8BfD8306A6a588302A6B931fa53fb6eb8E3292")
  
  const simpleConsumer = m.contract("FarcasterResolverSimpleConsumer", [eas, resolver], {});

  return { simpleConsumer };
});

export default FarcasterMembershipModule;