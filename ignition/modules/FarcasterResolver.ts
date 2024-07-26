import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { parseEther } from "viem";

const FarcasterResolverModule = buildModule("FarcasterResolverModule", (m) => {
  const admin = m.getAccount(0)

  const eas = m.contractAt("EAS", "0x4200000000000000000000000000000000000021");
  const resolver = m.contract("FarcasterResolver", [eas, admin], {});

  const keyRegistry = m.getParameter("keyRegistry", "0x00000000fc1237824fb747abde0ff18990e59b7e")
  const publicKeyVerifier = m.contract("FarcasterPublicKeyVerifier", [keyRegistry], {});

  const Ed25519_pow = m.library("Ed25519_pow")
  const Sha512 = m.library("Sha512")

  const Blake3 = m.library("Blake3")
  const Ed25519 = m.library("Ed25519", {
    libraries: {
      Ed25519_pow,
      Sha512,
    }
  })

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

  const schemaRegistry = m.contractAt("SchemaRegistry", "0x4200000000000000000000000000000000000020");

  m.call(schemaRegistry, "register", ["uint256 fid,address verifyAdrress,bytes32 publicKey,uint256 verificationMethod,bytes memory signature", resolver, true], { id: "registerSchema" })

  return { resolver, publicKeyVerifier, walletOnchainVerifier, walletOptimisticVerifier };
});

export default FarcasterResolverModule;