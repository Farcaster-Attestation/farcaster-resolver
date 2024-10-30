import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import FarcasterResolverMockModule from "../ignition/modules/FarcasterResolverMock";
import { MessageType, NobleEd25519Signer, VerificationAddAddressMessage, VerificationRemoveMessage } from "@farcaster/core";
import { signVerificationAddAddress, signVerificationRemoveAddress, toHexString } from "./utils";
import { encodeAbiParameters, getAddress, parseAbiParameters, PrivateKeyAccount } from "viem";

let fid: bigint;
let ed25519Signer: NobleEd25519Signer;

async function deployFixture() {
  const result = await ignition.deploy(FarcasterResolverMockModule);
  await result.publicKeyVerifier.write.addKey([
    fid,
    toHexString((await ed25519Signer.getSignerKey())._unsafeUnwrap()),
  ]);
  return result;
}

describe("Revoke Attestation", function () {
  let ethWallet: PrivateKeyAccount
  let addMessage: VerificationAddAddressMessage
  let addMessageBytes: Uint8Array
  let removeMessage: VerificationRemoveMessage
  let removeMessageBytes: Uint8Array

  before(async function () {
    const { fid: fid_, alice, message, messageBytes, ed25519Signer: ed25519Signer_ } = await signVerificationAddAddress();
    
    fid = fid_;
    ed25519Signer = ed25519Signer_;
    ethWallet = alice;
    addMessage = message;
    addMessageBytes = messageBytes;

    const { message: message__, messageBytes: messageBytes__ } = await signVerificationRemoveAddress(fid, ethWallet, ed25519Signer);

    removeMessage = message__;
    removeMessageBytes = messageBytes__;
  });

  it("OnchainVerifier revoke", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    const result = await publicKeyVerifier.read.verifyPublicKey([
      fid,
      toHexString((await ed25519Signer.getSignerKey())._unsafeUnwrap()),
    ]);
    expect(result).to.equal(true);
  });

  it("OnchainVerifier revoke", async function () {
    const { walletOnchainVerifier, eas, resolver } = await loadFixture(
      deployFixture
    );

    let uid: `0x${string}`;

    const publicClient = await hre.viem.getPublicClient();

    {
      const message = addMessage;
      const messageBytes = addMessageBytes;

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
    
      // Must not be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal(false)

      expect(
        await resolver.read.getAttestationUid([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal('0x0000000000000000000000000000000000000000000000000000000000000000')

      const hash = await resolver.write.attest([
        toHexString(message.data.verificationAddAddressBody.address),
        fid,
        toHexString(message.signer),
        1n,
        encodedData,
      ]);
      
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      uid = receipt.logs.find(log => log.topics[0] == '0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35')!.data

      // Must be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal(true)

      expect(
        await resolver.read.getAttestationUid([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal(uid)

      // Mapping must be updated
      expect(
        await resolver.read.getWalletAttestations([
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.deep.equal([
        [fid],
        [uid],
      ])

      expect(
        await resolver.read.getFidAttestations([
          fid,
        ])
      ).to.deep.equal([
        [getAddress(toHexString(message.data.verificationAddAddressBody.address))],
        [uid],
      ])
    }

    {
      const message = removeMessage
      const messageBytes = removeMessageBytes

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      const result = await walletOnchainVerifier.read.verifyRemove([
        fid,
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(true);

      // Must be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.equal(true)

      const hash = await resolver.write.revoke([
        toHexString(message.data.verificationRemoveBody.address),
        fid,
        toHexString(message.signer),
        1n,
        encodedData,
      ]);

      await publicClient.waitForTransactionReceipt({ hash })

      // Must not be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.equal(false)

      expect(
        await resolver.read.getAttestationUid([
          fid,
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000")

      // Mapping must be updated
      expect(
        await resolver.read.getWalletAttestations([
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.deep.equal([
        [],
        [],
      ])

      expect(
        await resolver.read.getFidAttestations([
          fid,
        ])
      ).to.deep.equal([
        [],
        [],
      ])
    }
  });

  it("OptimisticVerifier revoke", async function () {
    const { walletOptimisticVerifier, eas, resolver } = await loadFixture(
      deployFixture
    );

    let uid: `0x${string}`;

    const publicClient = await hre.viem.getPublicClient();

    {
      const message = addMessage
      const messageBytes = addMessageBytes

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
    
      // Must not be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal(false)

      expect(
        await resolver.read.getAttestationUid([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal('0x0000000000000000000000000000000000000000000000000000000000000000')

      const hash = await resolver.write.attest([
        toHexString(message.data.verificationAddAddressBody.address),
        fid,
        toHexString(message.signer),
        2n,
        encodedData,
      ]);
      
      const receipt = await publicClient.waitForTransactionReceipt({ hash })
      uid = receipt.logs.find(log => log.topics[0] == '0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35')!.data

      // Must be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal(true)

      expect(
        await resolver.read.getAttestationUid([
          fid,
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.equal(uid)

      // Mapping must be updated
      expect(
        await resolver.read.getWalletAttestations([
          toHexString(message.data.verificationAddAddressBody.address),
        ])
      ).to.deep.equal([
        [fid],
        [uid],
      ])

      expect(
        await resolver.read.getFidAttestations([
          fid,
        ])
      ).to.deep.equal([
        [getAddress(toHexString(message.data.verificationAddAddressBody.address))],
        [uid],
      ])
    }

    {
      const message = removeMessage
      const messageBytes = removeMessageBytes

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      await walletOptimisticVerifier.write.submitVerification([
        MessageType.VERIFICATION_REMOVE,
        fid,
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      await time.increase(86400);

      const result = await walletOptimisticVerifier.read.verifyRemove([
        fid,
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);
  
      expect(result).to.equal(true);

      // Must be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.equal(true)

      const hash = await resolver.write.revoke([
        toHexString(message.data.verificationRemoveBody.address),
        fid,
        toHexString(message.signer),
        2n,
        encodedData,
      ]);

      await publicClient.waitForTransactionReceipt({ hash })

      // Must not be verified
      expect(
        await resolver.read.isVerified([
          fid,
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.equal(false)

      expect(
        await resolver.read.getAttestationUid([
          fid,
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.equal("0x0000000000000000000000000000000000000000000000000000000000000000")

      // Mapping must be updated
      expect(
        await resolver.read.getWalletAttestations([
          toHexString(message.data.verificationRemoveBody.address),
        ])
      ).to.deep.equal([
        [],
        [],
      ])

      expect(
        await resolver.read.getFidAttestations([
          fid,
        ])
      ).to.deep.equal([
        [],
        [],
      ])
    }
  });

  it("Valid remove signature can't be challenged", async function () {
    const { walletOptimisticVerifier } = await loadFixture(deployFixture);
    const message = removeMessage;
    const messageBytes = removeMessageBytes;

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
      [
        toHexString(message.signature.subarray(0, 32)),
        toHexString(message.signature.subarray(32)),
        toHexString(messageBytes),
      ]
    );

    await walletOptimisticVerifier.write.submitVerification([
      MessageType.VERIFICATION_REMOVE,
      BigInt(message.data.fid),
      toHexString(message.data.verificationRemoveBody.address),
      toHexString(message.signer),
      encodedData,
    ]);

    expect(
      walletOptimisticVerifier.write.challengeRemove([
        BigInt(message.data.fid),
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ])
    ).to.be.rejectedWith("ChallengeFailed()")

    const challenged = await walletOptimisticVerifier.read.tryChallengeRemove([
      BigInt(message.data.fid),
      toHexString(message.data.verificationRemoveBody.address),
      toHexString(message.signer),
      encodedData,
    ]);

    expect(challenged).to.equal(false);
  });
});
