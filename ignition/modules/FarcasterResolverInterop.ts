import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"

const FarcasterResolverInteropModule = buildModule("FarcasterResolverInteropModule", (m) => {
  const { resolver, ...rest } = m.useModule(FarcasterResolverModule)
  
  const interop = m.contract("FarcasterResolverInterop", [resolver, m.getParameter("sourceChainId", 31337)], {});

  return { resolver, interop, ...rest };
});

export default FarcasterResolverInteropModule;