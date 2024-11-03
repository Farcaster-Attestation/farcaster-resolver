import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";
import FarcasterResolverModule from "./FarcasterResolver"

const FarcasterResolverSimpleConsumerModule = buildModule("FarcasterResolverSimpleConsumerModule", (m) => {
  const { resolver, eas } = m.useModule(FarcasterResolverModule)
  
  const simpleConsumer = m.contract("FarcasterResolverSimpleConsumer", [eas, resolver], {});

  return { simpleConsumer, resolver };
});

export default FarcasterResolverSimpleConsumerModule;