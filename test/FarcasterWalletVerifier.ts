import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import FarcasterResolverModule from "../ignition/modules/FarcasterResolver";
import {
  FarcasterNetwork,
  MessageData,
  MessageType,
  NobleEd25519Signer,
  Protocol,
  ViemLocalEip712Signer,
  makeVerificationAddEthAddress,
  makeVerificationRemove,
} from "@farcaster/core";
import { privateKeyToAccount } from 'viem/accounts';
import { randomBytes } from "crypto";
import { fromHexString, toHexString } from "./utils";
import { encodeAbiParameters, parseAbiParameters } from "viem";

async function deployFixture() {
  return ignition.deploy(FarcasterResolverModule);
}

async function signVerificationAddAddress() {
  const fid = 1n;

  const alice = privateKeyToAccount(`0x${Buffer.from(randomBytes(32)).toString('hex')}`);
  const eip712Signer: ViemLocalEip712Signer = new ViemLocalEip712Signer(alice as any);
  
  const ed25519Signer = new NobleEd25519Signer(randomBytes(32));

  const blockHash = randomBytes(32)

  const ethSignature = await eip712Signer.signVerificationEthAddressClaim({
    fid,
    address: alice.address as `0x${string}`,
    network: FarcasterNetwork.MAINNET,
    blockHash: `0x${Buffer.from(blockHash).toString('hex')}` as `0x${string}`,
    protocol: Protocol.ETHEREUM,
  });

  expect(ethSignature.isOk()).to.be.true

  const messageResult = await makeVerificationAddEthAddress(
    {
      address: fromHexString(alice.address),
      blockHash,
      claimSignature: ethSignature._unsafeUnwrap(),
      verificationType: 0,
      chainId: 0,
      protocol: Protocol.ETHEREUM,
    },
    { fid: Number(fid), network: FarcasterNetwork.MAINNET },
    ed25519Signer
  );

  expect(messageResult.isOk()).to.be.true

  const message = messageResult._unsafeUnwrap()

  const messageBytes = (MessageData.encode(message.data).finish());

  return {
    fid,
    alice,
    message,
    messageBytes,
  }
}

describe("FarcasterWalletOnchainVerifier", function () {
  it("Valid signature", async function () {
    const { walletOnchainVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } = await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters('bytes32 r, bytes32 s, bytes message'),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    )

    const result = await walletOnchainVerifier.read.verifyAdd(
      [
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]
    )

    expect(result).to.equal(true);
  });

  it("Invalid signature", async function () {
    const { walletOnchainVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } = await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters('bytes32 r, bytes32 s, bytes message'),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(randomBytes(32)),
        toHexString(messageBytes),
      ]
    )

    const result = await walletOnchainVerifier.read.verifyAdd(
      [
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]
    )

    expect(result).to.equal(false);
  });

  it("Invalid claim signature", async function () {
    const { walletOnchainVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message } = await signVerificationAddAddress();

    message.data.verificationAddAddressBody.claimSignature = randomBytes(65)
    const messageBytes = (MessageData.encode(message.data).finish())

    const encodedData = encodeAbiParameters(
      parseAbiParameters('bytes32 r, bytes32 s, bytes message'),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    )

    const result = await walletOnchainVerifier.read.verifyAdd(
      [
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]
    )

    expect(result).to.equal(false);
  });


  // it("Invalid claim signature", async function () {
  //   const { publicKeyVerifier } = await loadFixture(deployFixture);

  //   expect(await publicKeyVerifier.read.verifyPublicKey([100000000n, '0xbb77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  // });

  // it("Invalid public key", async function () {
  //   const { publicKeyVerifier } = await loadFixture(deployFixture);

  //   expect(await publicKeyVerifier.read.verifyPublicKey([328679n, '0xab77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  // });

  // it("Invalid both", async function () {
  //   const { publicKeyVerifier } = await loadFixture(deployFixture);

  //   expect(await publicKeyVerifier.read.verifyPublicKey([100000000n, '0xab77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  // });
});
