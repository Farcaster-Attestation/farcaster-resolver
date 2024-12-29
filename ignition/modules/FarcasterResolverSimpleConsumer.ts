import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverInteropModule from "./FarcasterResolverInterop";

const FarcasterResolverSimpleConsumerModule = buildModule("FarcasterResolverSimpleConsumerModule", (m) => {
  const { resolver, interop, eas } = m.useModule(FarcasterResolverInteropModule)
  
  const simpleConsumer = m.contract("FarcasterResolverSimpleConsumer", [eas, interop], {});

  return { simpleConsumer, resolver };
});

export default FarcasterResolverSimpleConsumerModule;