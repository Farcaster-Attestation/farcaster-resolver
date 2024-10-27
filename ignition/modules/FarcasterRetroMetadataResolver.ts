import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"
import FarcasterMembershipModule from "./FarcasterMembership"

const FarcasterRetroMetadataResolver = buildModule("FarcasterRetroMetadataResolver", (m) => {
  const { resolver, eas } = m.useModule(FarcasterResolverModule)
  const { membership } = m.useModule(FarcasterMembershipModule)
  
  const consumer = m.contract("FarcasterResolverStandardConsumer", [eas, resolver, membership, false, false, true, true, 32, 0], {});

  return { consumer };
});

export default FarcasterRetroMetadataResolver;