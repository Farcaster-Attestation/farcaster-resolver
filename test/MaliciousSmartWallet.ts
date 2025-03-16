import { loadFixture } from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { deployResolverWithAttestations, fromHexString, signVerificationAddAddress, toHexString } from "./utils";
import {
  readContract,
  getBalance,
  writeContract,
  simulateContract,
  waitForTransactionReceipt,
  getChainId,
} from "viem/actions";
import hre from "hardhat"; // Import the Hardhat Runtime Environment
import {
  FarcasterNetwork,
  HashScheme,
  MessageData,
  MessageType,
  NobleEd25519Signer,
  Protocol,
  SignatureScheme,
  VerificationAddAddressMessage,
  VerificationRemoveMessage,
  ViemLocalEip712Signer,
  ed25519,
  makeVerificationAddEthAddress,
  makeVerificationRemove,
} from "@farcaster/core";
import { expect } from "chai";
import { encodeAbiParameters, http, LocalAccount, toHex } from "viem";
import { parseAbiParameters } from "viem";
import { randomBytes } from "crypto";

export async function makeSignature(fid: bigint = 1n, alice: LocalAccount, walletAddress: `0x${string}`, ed25519Signer: NobleEd25519Signer) {
  const eip712Signer: ViemLocalEip712Signer = new ViemLocalEip712Signer(
    alice as any
  );

  const blockHash = randomBytes(32);
  const publicClient = await hre.viem.getPublicClient();
  const publicClients = { 10: publicClient }; // OPTIMISM
  
  const ethSignature = await eip712Signer.signVerificationEthAddressClaim({
    fid: BigInt(fid),
    address: walletAddress as `0x${string}`,
    network: FarcasterNetwork.MAINNET,
    blockHash: `0x${Buffer.from(blockHash).toString("hex")}` as `0x${string}`,
    protocol: Protocol.ETHEREUM,
  });

  expect(ethSignature.isOk()).to.be.true;

  const messageResult = await makeVerificationAddEthAddress(
    {
      address: fromHexString(walletAddress),
      blockHash,
      claimSignature: ethSignature._unsafeUnwrap(),
      verificationType: 1,
      chainId: 10,
      protocol: Protocol.ETHEREUM,
    },
    { fid: Number(fid), network: FarcasterNetwork.MAINNET },
    ed25519Signer,
    publicClients
  );

  expect(messageResult.isOk()).to.be.true;

  const message = messageResult._unsafeUnwrap();
  const messageBytes = MessageData.encode(message.data).finish();

  return {
    fid,
    message,
    messageResult,
    messageBytes,
    ed25519Signer,
  };
}

async function deployFixture() {
  const result = await deployResolverWithAttestations();

  // DEPLOY CONTRACT SIGNER
  const farcasterContractUser = await hre.viem.deployContract(
    "MaliciousSmartWallet",
  );

  return { result, farcasterContractUser };
}

describe("POC", function () {
  it.only("MaliciousSmartWallet", async function () {
    const {
      result,
      farcasterContractUser,
    } = await loadFixture(deployFixture);
    
    const publicKeyVerifier = result.publicKeyVerifier;
    const resolver = result.resolver;
    const walletOnchainVerifier = result.walletOnchainVerifier;
    const walletOptimisticVerifier = result.walletOptimisticVerifier;
    const membership = result.membership;
    const simpleConsumer = result.simpleConsumer;
    const schemaRegistry = result.schemaRegistry;
    const eas = result.eas;
    const alices = result.alices;
    const fids = result.fids; 
    const ed25519Signers = result.ed25519Signers;

    const fid = 1n;

    const { 
      fid: fid_, 
      message, messageResult, 
      messageBytes, 
      ed25519Signer: ed2519Signer_ 
    } = await makeSignature(
      fid, 
      alices[0], 
      farcasterContractUser.address, 
      ed25519Signers[0]
    );
    const pubKey = message.signer;

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );
    
    // RELAYER SUBMIT
    await expect(walletOptimisticVerifier.write.submitVerification([
      MessageType.VERIFICATION_ADD_ETH_ADDRESS,
      BigInt(fid),
      farcasterContractUser.address,
      toHexString(pubKey),
      BigInt(message.data.timestamp),
      encodedData,
    ])).to.be.rejectedWith("SmartContractWalletNotAllowed()");
  });
})

