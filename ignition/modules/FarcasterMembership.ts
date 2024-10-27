import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"

const FarcasterMembershipModule = buildModule("FarcasterMembershipModule", (m) => {
  const { resolver, eas } = m.useModule(FarcasterResolverModule)

  const membership = m.contract("FarcasterMembership", [eas, resolver], {});

  return { membership };
});

export default FarcasterMembershipModule;