import {
  Ed25519Signer,
  FarcasterNetwork,
  MessageData,
  NobleEd25519Signer,
  Protocol,
  VerificationAddAddressMessage,
  ViemLocalEip712Signer,
  makeMessageHash,
  makeVerificationAddEthAddress,
  makeVerificationRemove,
} from "@farcaster/core";
import { expect } from "chai";
import { randomBytes } from "crypto";
import hre, { ignition } from "hardhat";
import {
  encodeAbiParameters,
  parseAbiParameters,
  PrivateKeyAccount,
} from "viem";
import { time, mine } from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { privateKeyToAccount } from "viem/accounts";
import FarcasterResolverModule from "../ignition/modules/FarcasterResolver";
import TestSuiteModule from "../ignition/modules/TestSuite";

export interface Signature {
  r: Buffer;
  s: Buffer;
}

export const signFarcasterMessage = async (
  signer: Ed25519Signer,
  message_data: MessageData
): Promise<Signature> => {
  const message_hash = (await makeMessageHash(message_data))._unsafeUnwrap();

  const signature = (
    await signer.signMessageHash(message_hash)
  )._unsafeUnwrap();

  const [r, s] = [
    Buffer.from(signature.slice(0, 32)),
    Buffer.from(signature.slice(32, 64)),
  ];

  return { r, s };
};

export async function signVerificationAddAddress(fid: bigint = 1n) {
  const alice = privateKeyToAccount(
    `0x${Buffer.from(randomBytes(32)).toString("hex")}`
  );
  const eip712Signer: ViemLocalEip712Signer = new ViemLocalEip712Signer(
    alice as any
  );

  const ed25519Signer = new NobleEd25519Signer(randomBytes(32));

  const blockHash = randomBytes(32);

  const ethSignature = await eip712Signer.signVerificationEthAddressClaim({
    fid: BigInt(fid),
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
    ed25519Signer,
  };
}

export async function signVerificationRemoveAddress(
  fid: number | bigint = 1,
  alice: PrivateKeyAccount = privateKeyToAccount(
    `0x${Buffer.from(randomBytes(32)).toString("hex")}`
  ),
  ed25519Signer: NobleEd25519Signer = new NobleEd25519Signer(randomBytes(32))
) {
  const messageResult = await makeVerificationRemove(
    {
      address: fromHexString(alice.address),
      protocol: Protocol.ETHEREUM,
    },
    { fid: Number(fid), network: FarcasterNetwork.MAINNET },
    ed25519Signer
  );

  expect(messageResult.isOk()).to.be.true;

  const message = messageResult._unsafeUnwrap();

  const messageBytes = MessageData.encode(message.data).finish();

  return {
    fid: BigInt(fid),
    alice,
    message,
    messageBytes,
    ed25519Signer,
  };
}

export async function deployResolverWithAttestations() {
  const currentTimestamp = Math.floor(Date.now() / 1000);
  await time.setNextBlockTimestamp(currentTimestamp);
  await mine();

  const result = await ignition.deploy(TestSuiteModule);

  const fids = [1n, 2n, 3n, 4n];
  const alices: PrivateKeyAccount[] = [];
  const ed25519Signers: NobleEd25519Signer[] = [];
  const messages: VerificationAddAddressMessage[] = [];
  const messageBytes: Uint8Array[] = [];

  for (const fid of fids) {
    const {
      alice,
      message,
      messageBytes: messageBytes_,
      ed25519Signer,
    } = await signVerificationAddAddress(fid);

    alices.push(alice);
    ed25519Signers.push(ed25519Signer);
    messages.push(message);
    messageBytes.push(messageBytes_);

    await result.publicKeyVerifier.write.addKey([
      fid,
      toHexString((await ed25519Signer.getSignerKey())._unsafeUnwrap()),
    ]);

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes_),
      ]
    );

    await result.resolver.write.attest([
      toHexString(message.data.verificationAddAddressBody.address),
      fid,
      toHexString(message.signer),
      1n,
      encodedData,
    ]);
  }

  const [deployer] = await hre.viem.getWalletClients();
  for (let i = 0; i < 4; i++) {
    await deployer.sendTransaction({
      to: alices[i].address,
      value: 10000000000000000n // 0.1 ETH
    });
  }

  return {
    fids,
    alices,
    ed25519Signers,
    messages,
    messageBytes,
    ...result,
  };
}

export async function getAttestationUid(hash: `0x${string}`) {
  const publicClient = await hre.viem.getPublicClient();
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  const uid = receipt.logs.find(log => log.topics[0] == '0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35')!.data
  return uid;
}

export const fromHexString = (hexString: `0x${string}`) =>
  Uint8Array.from(
    hexString
      .substring(2)
      .match(/.{1,2}/g)!
      .map((byte) => parseInt(byte, 16))
  );

export const toHexString = (array: Uint8Array): `0x${string}` =>
  `0x${Buffer.from(array).toString("hex")}`;
