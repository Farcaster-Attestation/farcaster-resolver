import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"
import FarcasterMembershipModule from "./FarcasterMembership"

const FarcasterRetroMetadataResolver = buildModule("FarcasterRetroMetadataResolver", (m) => {
  // const { resolver, eas } = m.useModule(FarcasterResolverModule)
  const { membership } = m.useModule(FarcasterMembershipModule)

  const eas = m.contractAt("EAS", "0x4200000000000000000000000000000000000021");
  const resolver = m.contractAt("FarcasterResolver", "0xba8BfD8306A6a588302A6B931fa53fb6eb8E3292")
  
  const consumer = m.contract("FarcasterResolverStandardConsumer", [eas, resolver, membership, false, false, true, true, 32, 0], {});

  return { consumer };
});

export default FarcasterRetroMetadataResolver;