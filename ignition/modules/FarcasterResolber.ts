import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";

const FarcasterResolverModule = buildModule("FarcasterResolverModule", (m) => {
  const eas = m.getParameter("eas", "0xC2679fBD37d54388Ce493F1DB75320D236e1815e");
  const resolver = m.contract("FarcasterResolver", [eas], {});

  return { resolver };
});

export default FarcasterResolverModule;