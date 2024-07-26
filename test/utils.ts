import { Ed25519Signer, MessageData, makeMessageHash } from "@farcaster/core";

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

export const fromHexString = (hexString: `0x${string}`) =>
  Uint8Array.from((hexString.substring(2).match(/.{1,2}/g)!).map((byte) => parseInt(byte, 16)));

export const toHexString = (array: Uint8Array): `0x${string}` => `0x${Buffer.from(array).toString('hex')}`