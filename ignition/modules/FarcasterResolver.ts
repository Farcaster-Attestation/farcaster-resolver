import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";

const FarcasterResolverModule = buildModule("FarcasterResolverModule", (m) => {
  const admin = m.getAccount(0)

  const eas = m.getParameter("eas", "0x4200000000000000000000000000000000000021");
  const resolver = m.contract("FarcasterResolver", [eas, admin], {});

  const keyRegistry = m.getParameter("keyRegistry", "0x00000000fc1237824fb747abde0ff18990e59b7e")
  const publicKeyVerifier = m.contract("FarcasterPublicKeyVerifier", [keyRegistry], {});

  const Blake3 = m.library("Blake3")
  const Ed25519 = m.library("Ed25519_pow")
  const FcMessageVerification = m.library("FcMessageVerification", {
    libraries: {
      Blake3,
      Ed25519,
    }
  })
  const FcVerificationDecoder = m.library("FcVerificationDecoder")

  const walletOnchainVerifier = m.contract("FarcasterWalletOnchainVerifier", [], {
    libraries: {
      FcMessageVerification,
      FcVerificationDecoder,
    }
  })

  const walletOptimisticVerifier = m.contract("FarcasterWalletOptimisticVerifier", [walletOnchainVerifier, admin], {})

  m.call(resolver, "setPublicKeyVerifier", [publicKeyVerifier])
  m.call(resolver, "setVerifier", [1, walletOnchainVerifier], { id: "setWalletOnchainVerifier" })
  m.call(resolver, "setVerifier", [2, walletOptimisticVerifier], { id: "setWalletOptimisticVerifier" })

  return { resolver, publicKeyVerifier, walletOnchainVerifier, walletOptimisticVerifier };
});

export default FarcasterResolverModule;