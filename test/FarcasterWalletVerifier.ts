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
  VerificationRemoveMessage,
  ViemLocalEip712Signer,
  makeVerificationAddEthAddress,
  makeVerificationRemove,
} from "@farcaster/core";
import { privateKeyToAccount } from "viem/accounts";
import { randomBytes } from "crypto";
import { fromHexString, signVerificationAddAddress, signVerificationRemoveAddress, toHexString } from "./utils";
import {
  encodeAbiParameters,
  encodePacked,
  getAddress,
  keccak256,
  parseAbiParameters,
  PrivateKeyAccount,
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

describe("FarcasterWalletVerifier", function () {
  let ethWallet: PrivateKeyAccount
  let addMessage: VerificationAddAddressMessage
  let addMessageBytes: Uint8Array
  let removeMessage: VerificationRemoveMessage
  let removeMessageBytes: Uint8Array
  let fid: bigint;
  let ed25519Signer: NobleEd25519Signer;

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

  async function deployFixture() {
    const result = await ignition.deploy(FarcasterResolverModule);
    await result.publicKeyVerifier.write.addKey([
      fid,
      toHexString((await ed25519Signer.getSignerKey())._unsafeUnwrap()),
    ]);
    return result;
  }

  it("External verification", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    const result = await publicKeyVerifier.read.verifyPublicKey([
      fid,
      toHexString((await ed25519Signer.getSignerKey())._unsafeUnwrap()),
    ]);
    expect(result).to.equal(true);
  });

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

    it("Valid remove signature", async function () {
      const { walletOnchainVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } = 
        await signVerificationRemoveAddress();

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

      {
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
      }

      {
        const encodedData = encodeAbiParameters(
          parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
          [
            toHexString(message.signature.subarray(0, 32)),
            toHexString(message.signature.subarray(32)),
            toHexString(messageBytes),
          ]
        );
    
        const result = await walletOnchainVerifier.read.verifyAdd([
          fid + 1n,
          alice.address,
          toHexString(message.signer),
          encodedData,
        ]);
    
        expect(result).to.equal(false);
      }

      {
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
          "0x0000000000000000000000000000000000000000",
          toHexString(message.signer),
          encodedData,
        ]);
    
        expect(result).to.equal(false);
      }
    });

    it("Invalid remove signature", async function () {
      const { walletOnchainVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } =
        await signVerificationRemoveAddress();

      {
        const encodedData = encodeAbiParameters(
          parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
          [
            toHexString(message.signature.subarray(0, 32)),
            toHexString(randomBytes(32)),
            toHexString(messageBytes),
          ]
        );
    
        const result = await walletOnchainVerifier.read.verifyRemove([
          fid, 
          alice.address,
          toHexString(message.signer),
          encodedData,
        ]);

        expect(result).to.equal(false);
      }

      {
        const encodedData = encodeAbiParameters(
          parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
          [
            toHexString(message.signature.subarray(0, 32)),
            toHexString(message.signature.subarray(32)),
            toHexString(messageBytes),
          ]
        );
    
        const result = await walletOnchainVerifier.read.verifyRemove([
          fid + 1n, 
          alice.address,
          toHexString(message.signer),
          encodedData,
        ]);

        expect(result).to.equal(false);
      }

      {
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
          "0x0000000000000000000000000000000000000000",
          toHexString(message.signer),
          encodedData,
        ]);

        expect(result).to.equal(false);
      }
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

      const publicClient = await hre.viem.getPublicClient();

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
        const uid = receipt.logs.find(log => log.topics[0] == '0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35')!.data

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
    });

    it("Revoke", async function () {
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
  });

  describe("FarcasterWalletOptimisticVerifier", function () {
    it("Valid signature but not submitted", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const message = REAL_VERIFICATION;
      const messageBytes = MessageData.encode(REAL_VERIFICATION.data).finish();

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      const result = await walletOptimisticVerifier.read.verifyAdd([
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Valid signature but not wait 1 day", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const message = REAL_VERIFICATION;
      const messageBytes = MessageData.encode(REAL_VERIFICATION.data).finish();

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
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      const result = await walletOptimisticVerifier.read.verifyAdd([
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Valid signature and wait 1 day", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const message = REAL_VERIFICATION;
      const messageBytes = MessageData.encode(REAL_VERIFICATION.data).finish();

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
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      await time.increase(86400);

      const result = await walletOptimisticVerifier.read.verifyAdd([
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(true);
    });

    it("Valid signature can't be challenged", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const message = REAL_VERIFICATION;
      const messageBytes = MessageData.encode(REAL_VERIFICATION.data).finish();

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
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(
        walletOptimisticVerifier.write.challengeAdd([
          BigInt(message.data.fid),
          toHexString(message.data.verificationAddAddressBody.address),
          toHexString(message.signer),
          encodedData,
        ])
      ).to.be.rejectedWith("ChallengeFailed()")

      const challenged = await walletOptimisticVerifier.read.tryChallengeAdd([
        BigInt(message.data.fid),
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(challenged).to.equal(false);
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

      const challenged = await walletOptimisticVerifier.read.tryChallengeAdd([
        fid,
        alice.address, 
        toHexString(message.signer),
        encodedData
      ]);

      expect(challenged).to.equal(true);

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

    it("Valid signature but invalid public key challenged", async function () {
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

      await time.increase(16400);

      const challenged = await walletOptimisticVerifier.read.tryChallengeAdd([
        fid,
        alice.address, 
        toHexString(message.signer),
        encodedData
      ]);

      expect(challenged).to.equal(true);

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

    it("Valid remove signature but not submitted", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress();

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      const result = await walletOptimisticVerifier.read.verifyRemove([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Valid remove signature but not wait 1 day", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress();

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
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      const result = await walletOptimisticVerifier.read.verifyRemove([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Valid remove signature and wait 1 day", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress();

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
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      await time.increase(86400);

      const result = await walletOptimisticVerifier.read.verifyRemove([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(true);
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

    it("Valid remove signature but invalid public key challenged", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress();

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
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      await time.increase(16400);

      const challenged = await walletOptimisticVerifier.read.tryChallengeRemove([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      expect(challenged).to.equal(true);

      await walletOptimisticVerifier.write.challengeRemove([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      await time.increase(86400);

      const result = await walletOptimisticVerifier.read.verifyRemove([
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

      const publicClient = await hre.viem.getPublicClient();

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
        const uid = receipt.logs.find(log => log.topics[0] == '0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35')!.data

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
    });

    it("Revoke", async function () {
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
  });

})
