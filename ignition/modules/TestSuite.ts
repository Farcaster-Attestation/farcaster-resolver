import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import FarcasterResolverModule from "./FarcasterResolver"
import FarcasterMembershipModule from "./FarcasterMembership";
import FarcasterResolverSimpleConsumerModule from "./FarcasterResolverSimpleConsumer";

const TestSuiteModule = buildModule("TestSuiteModule", (m) => {
  const a = m.useModule(FarcasterResolverModule)
  const b = m.useModule(FarcasterMembershipModule)
  const c = m.useModule(FarcasterResolverSimpleConsumerModule)

  return {
    ...a,
    ...b,
    ...c,
  };
});

export default TestSuiteModule;