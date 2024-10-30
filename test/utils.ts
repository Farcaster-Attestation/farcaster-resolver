import { Ed25519Signer, FarcasterNetwork, MessageData, NobleEd25519Signer, Protocol, ViemLocalEip712Signer, makeMessageHash, makeVerificationAddEthAddress, makeVerificationRemove } from "@farcaster/core";
import { expect } from "chai";
import { randomBytes } from "crypto";
import { PrivateKeyAccount } from "viem";
import { privateKeyToAccount } from "viem/accounts";

export interface Signature {
  r: Buffer,
  s: Buffer,
}

export const signFarcasterMessage = async (
  signer: Ed25519Signer,
  message_data: MessageData
): Promise<Signature> => {
  const message_hash = (await makeMessageHash(message_data))._unsafeUnwrap();
  
  const signature = (await signer.signMessageHash(message_hash))._unsafeUnwrap();

  const [
    r, s
  ] = [
    Buffer.from(signature.slice(0, 32)),
    Buffer.from(signature.slice(32, 64))
  ];

  return { r, s };
}

export async function signVerificationAddAddress() {
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
  const messageResult = await makeVerificationRemove({
    address: fromHexString(alice.address),
    protocol: Protocol.ETHEREUM,
  }, { fid: Number(fid), network: FarcasterNetwork.MAINNET }, ed25519Signer)

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

export const fromHexString = (hexString: `0x${string}`) =>
  Uint8Array.from((hexString.substring(2).match(/.{1,2}/g)!).map((byte) => parseInt(byte, 16)));

export const toHexString = (array: Uint8Array): `0x${string}` => `0x${Buffer.from(array).toString('hex')}`