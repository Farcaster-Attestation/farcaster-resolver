import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const FarcasterPublicKeyVerifierModule = buildModule(
  "FarcasterPublicKeyVerifierModule",
  (m) => {
    const admin = m.getAccount(0);
    const keyRegistry = m.getParameter(
      "keyRegistry",
      "0x00000000fc1237824fb747abde0ff18990e59b7e"
    );

    const publicKeyVerifier = m.contract(
      "FarcasterPublicKeyVerifier",
      [keyRegistry, admin],
      {}
    );

    return { publicKeyVerifier };
  }
);

export default FarcasterPublicKeyVerifierModule;
