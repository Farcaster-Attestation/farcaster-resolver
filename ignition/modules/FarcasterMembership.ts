import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverInteropModule from "./FarcasterResolverInterop";

const FarcasterMembershipModule = buildModule("FarcasterMembershipModule", (m) => {
  const { resolver, interop, eas } = m.useModule(FarcasterResolverInteropModule)

  const membership = m.contract("FarcasterMembership", [eas, interop], {});

  return { membership };
});

export default FarcasterMembershipModule;