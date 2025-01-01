import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const FarcasterResolverExtendedModule = buildModule("FarcasterResolverExtendedModule", (m) => {
  const eas = m.contractAt("EAS", "0x4200000000000000000000000000000000000021");
  const interop = m.contract("FarcasterResolverInterop", [m.getParameter("resolverAddress"), m.getParameter("sourceChainId", 31337)], {});
  const membership = m.contract("FarcasterMembership", [eas, interop], {});
  const simpleConsumer = m.contract("FarcasterResolverSimpleConsumer", [eas, interop], {});

  return {
    eas,
    interop,
    membership,
    simpleConsumer,
  };
});

export default FarcasterResolverExtendedModule;