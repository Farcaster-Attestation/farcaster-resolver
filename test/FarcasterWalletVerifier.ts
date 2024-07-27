import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import FarcasterResolverModule from "../ignition/modules/FarcasterResolver";
import {
  FarcasterNetwork,
  HashScheme,
  MessageData,
  MessageType,
  NobleEd25519Signer,
  Protocol,
  SignatureScheme,
  VerificationAddAddressMessage,
  ViemLocalEip712Signer,
  makeVerificationAddEthAddress,
  makeVerificationRemove,
} from "@farcaster/core";
import { privateKeyToAccount } from "viem/accounts";
import { randomBytes } from "crypto";
import { fromHexString, toHexString } from "./utils";
import {
  encodeAbiParameters,
  encodePacked,
  keccak256,
  parseAbiParameters,
} from "viem";

const REAL_VERIFICATION: VerificationAddAddressMessage = {
  data: {
    type: MessageType.VERIFICATION_ADD_ETH_ADDRESS,
    fid: 328679,
    timestamp: 100412508,
    network: FarcasterNetwork.MAINNET,
    verificationAddAddressBody: {
      address: fromHexString("0xf01dd015bc442d872275a79b9cae84a6ff9b2a27"),
      claimSignature: Buffer.from(
        "IsbQTvpf5U1v31NcLHuJS6UeThEQLx1cyVVr5lZ0w7UN2TDKzVdyx6qpKdjwnTmjJ/xfG6s0oNbcNB2PlG+FFhw=",
        "base64"
      ),
      blockHash: fromHexString(
        "0x39dfd535c2173c551c4ed55dbb2d52a07951cd68852547509ce066720d251473"
      ),
      verificationType: 0,
      chainId: 0,
      protocol: Protocol.ETHEREUM,
    },
  },
  hash: fromHexString("0x4576a545b9ddda33e3629e84ae86f8b904c106d5"),
  hashScheme: HashScheme.BLAKE3,
  signature: Buffer.from(
    "j2EmRG5mjZNzXgFfdNphfR+6/9FHHDzV9ZFGLTVuOJBrgK/fWt7L6dyMdCOyqig6M3LbHCXDPTL+McDFQcOGDA==",
    "base64"
  ),
  signatureScheme: SignatureScheme.ED25519,
  signer: fromHexString(
    "0xbb77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a"
  ),
};

async function deployFixture() {
  return ignition.deploy(FarcasterResolverModule);
}

async function signVerificationAddAddress() {
  const fid = 1n;

  const alice = privateKeyToAccount(
    `0x${Buffer.from(randomBytes(32)).toString("hex")}`
  );
  const eip712Signer: ViemLocalEip712Signer = new ViemLocalEip712Signer(
    alice as any
  );

  const ed25519Signer = new NobleEd25519Signer(randomBytes(32));

  const blockHash = randomBytes(32);

  const ethSignature = await eip712Signer.signVerificationEthAddressClaim({
    fid,
    address: alice.address as `0x${string}`,
    network: FarcasterNetwork.MAINNET,
    blockHash: `0x${Buffer.from(blockHash).toString("hex")}` as `0x${string}`,
    protocol: Protocol.ETHEREUM,
  });

  expect(ethSignature.isOk()).to.be.true;

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

  expect(messageResult.isOk()).to.be.true;

  const message = messageResult._unsafeUnwrap();

  const messageBytes = MessageData.encode(message.data).finish();

  return {
    fid,
    alice,
    message,
    messageBytes,
  };
}

const SCHEMA =
  "uint256 fid,bytes32 publicKey,uint256 verificationMethod,bytes memory signature";

function getSchemaId(resolver: `0x${string}`) {
  // Encode packed the schema, resolver, and revocable fields
  const encodedData = encodePacked(
    ["string", "address", "bool"],
    [SCHEMA, resolver, true]
  );

  // Compute the keccak256 hash of the encoded data
  const hash = keccak256(encodedData);

  return hash;
}

describe("FarcasterWalletOnchainVerifier", function () {
  it("Valid signature", async function () {
    const { walletOnchainVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } =
      await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    const result = await walletOnchainVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(true);
  });

  it("Invalid signature", async function () {
    const { walletOnchainVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } =
      await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(randomBytes(32)),
        toHexString(messageBytes),
      ]
    );

    const result = await walletOnchainVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(false);
  });

  it("Invalid claim signature", async function () {
    const { walletOnchainVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message } = await signVerificationAddAddress();

    message.data.verificationAddAddressBody.claimSignature = randomBytes(65);
    const messageBytes = MessageData.encode(message.data).finish();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    const result = await walletOnchainVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(false);
  });

  it("Attest", async function () {
    const { walletOnchainVerifier, eas, resolver } = await loadFixture(
      deployFixture
    );

    const message = REAL_VERIFICATION;
    const messageBytes = MessageData.encode(REAL_VERIFICATION.data).finish();

    const fid = BigInt(message.data.fid);

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    const result = await walletOnchainVerifier.read.verifyAdd([
      fid,
      toHexString(message.data.verificationAddAddressBody.address),
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(true);

    {
      const schemaId = getSchemaId(resolver.address);
      const body = encodeAbiParameters(parseAbiParameters(SCHEMA), [
        fid,
        toHexString(message.signer),
        1n,
        encodedData,
      ]);

      await eas.write.attest([
        {
          schema: schemaId,
          data: {
            recipient: toHexString(message.data.verificationAddAddressBody.address),
            data: body,
            expirationTime: 0n,
            revocable: true,
            refUID:
              "0x0000000000000000000000000000000000000000000000000000000000000000",
            value: 0n,
          },
        },
      ]);
    }
  });
});

describe("FarcasterWalletOptimisticVerifier", function () {
  it("Valid signature but not submitted", async function () {
    const { walletOptimisticVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } =
      await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    const result = await walletOptimisticVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(false);
  });

  it("Valid signature but not wait 1 day", async function () {
    const { walletOptimisticVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } =
      await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    await walletOptimisticVerifier.write.submitVerification([
      MessageType.VERIFICATION_ADD_ETH_ADDRESS,
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    const result = await walletOptimisticVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(false);
  });

  it("Valid signature and wait 1 day", async function () {
    const { walletOptimisticVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } =
      await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    await walletOptimisticVerifier.write.submitVerification([
      MessageType.VERIFICATION_ADD_ETH_ADDRESS,
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    await time.increase(86400);

    const result = await walletOptimisticVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(true);
  });

  it("Invalid signature challenged", async function () {
    const { walletOptimisticVerifier } = await loadFixture(deployFixture);
    const { fid, alice, message, messageBytes } =
      await signVerificationAddAddress();

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(randomBytes(32)),
        toHexString(messageBytes),
      ]
    );

    await walletOptimisticVerifier.write.submitVerification([
      MessageType.VERIFICATION_ADD_ETH_ADDRESS,
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    await time.increase(16400);

    await walletOptimisticVerifier.write.challengeAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    await time.increase(86400);

    const result = await walletOptimisticVerifier.read.verifyAdd([
      fid,
      alice.address,
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(false);
  });

  it("Attest", async function () {
    const { walletOptimisticVerifier, eas, resolver } = await loadFixture(
      deployFixture
    );

    const message = REAL_VERIFICATION;
    const messageBytes = MessageData.encode(REAL_VERIFICATION.data).finish();

    const fid = BigInt(message.data.fid);

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    await walletOptimisticVerifier.write.submitVerification([
      MessageType.VERIFICATION_ADD_ETH_ADDRESS,
      fid,
      toHexString(message.data.verificationAddAddressBody.address),
      toHexString(message.signer),
      encodedData,
    ]);

    await time.increase(86400);

    const result = await walletOptimisticVerifier.read.verifyAdd([
      fid,
      toHexString(message.data.verificationAddAddressBody.address),
      toHexString(message.signer),
      encodedData,
    ]);

    expect(result).to.equal(true);

    {
      const schemaId = getSchemaId(resolver.address);
      const body = encodeAbiParameters(parseAbiParameters(SCHEMA), [
        fid,
        toHexString(message.signer),
        2n,
        encodedData,
      ]);

      await eas.write.attest([
        {
          schema: schemaId,
          data: {
            recipient: toHexString(message.data.verificationAddAddressBody.address),
            data: body,
            expirationTime: 0n,
            revocable: true,
            refUID:
              "0x0000000000000000000000000000000000000000000000000000000000000000",
            value: 0n,
          },
        },
      ]);
    }
  });
});
