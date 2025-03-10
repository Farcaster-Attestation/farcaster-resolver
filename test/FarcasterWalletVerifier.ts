import {
  time,
  loadFixture,
  impersonateAccount,
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
  getContract,
  keccak256,
  parseAbiParameters,
  parseEther,
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
  let removeMessageBytes: Uint8Array
  let removeMessage: VerificationRemoveMessage
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

        {
          const encodedData = encodeAbiParameters(
            parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
            [
              toHexString(message.signature.subarray(0, 32)),
              toHexString(randomBytes(32)),
              toHexString(messageBytes),
            ]
          );

          const { result } = await resolver.simulate.revoke([
            toHexString(message.data.verificationRemoveBody.address),
            fid,
            toHexString(message.signer),
            1n,
            encodedData,
          ]);

          expect(result).to.be.false
        }
  
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

      await expect(
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

    it("Valid signature can't be challenged if gas limit is too low", async function () {
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
    
      let gasLimit = 1_000_000;
      
      await expect(
        walletOptimisticVerifier.write.challengeAdd([
          BigInt(message.data.fid),
          toHexString(message.data.verificationAddAddressBody.address),
          toHexString(message.signer),
          encodedData
        ], {gas: BigInt(gasLimit)}) // Uncomment the expect reject to see that the test fails because the transaction succeeds.
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
      const [ wallet1 ] = await hre.viem.getWalletClients()
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } =
        await signVerificationAddAddress();

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

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

      await expect(walletOptimisticVerifier.read.verifyAdd([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ])).to.be.rejectedWith(`NotEnoughDeposit(${parseEther('0.015')})`)

      await wallet1.sendTransaction({
        to: walletOptimisticVerifier.address,
        value: parseEther('0.005'),
      })

      const result = await walletOptimisticVerifier.read.verifyAdd([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Invalid signature challenged until reward depleted", async function () {
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(deployFixture);

      const challengeArgs: [bigint, `0x${string}`, `0x${string}`, `0x${string}`][] = []

      for (let i = 0; i < 5; i++) {
        const { fid, alice, message, messageBytes } = await signVerificationAddAddress(BigInt(i + 10));

        await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

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

        challengeArgs.push([
          fid,
          alice.address, 
          toHexString(message.signer),
          encodedData
        ])
      }

      await time.increase(16400);

      for (let i = 0; i < 5; i++) {
        const challenged = await walletOptimisticVerifier.read.tryChallengeAdd(challengeArgs[i]);

        expect(challenged).to.equal(true);

        await walletOptimisticVerifier.write.challengeAdd(challengeArgs[i]);
      }

      await time.increase(86400);

      for (let i = 0; i < 5; i++) {
        await expect(walletOptimisticVerifier.read.verifyAdd(challengeArgs[i])).to.be.rejectedWith(`NotEnoughDeposit(0)`)
      }
    });

    it("Can't submit verification without enough deposit", async function () {
      const [ wallet1 ] = await hre.viem.getWalletClients()
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } =
        await signVerificationAddAddress();

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

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

      await walletOptimisticVerifier.write.challengeAdd([
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);

      await expect(walletOptimisticVerifier.write.submitVerification([
        MessageType.VERIFICATION_ADD_ETH_ADDRESS,
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ])).to.be.rejectedWith(`NotEnoughDeposit(${parseEther('0.015')})`);
    });

    it("Valid signature but invalid public key can't be submitted", async function () {
      const [ wallet1 ] = await hre.viem.getWalletClients()
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

      await expect(walletOptimisticVerifier.write.submitVerification([
        MessageType.VERIFICATION_ADD_ETH_ADDRESS,
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ])).to.be.rejectedWith(`InvalidPublicKey(${fid}, "${toHexString(message.signer)}")`);

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

      const result = await walletOptimisticVerifier.read.verifyRemove([
        fid,
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Valid remove signature but not wait 1 day", async function () {
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
        fid,
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      const result = await walletOptimisticVerifier.read.verifyRemove([
        fid,
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(result).to.equal(false);
    });

    it("Valid remove signature and wait 1 day", async function () {
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
  
      await expect(
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

    it("Invalid remove signature challenged", async function () {
      const { walletOptimisticVerifier } = await loadFixture(deployFixture);
      const message = removeMessage;
      const messageBytes = removeMessageBytes;
  
      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(randomBytes(32)),
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
  
      await walletOptimisticVerifier.write.challengeRemove([
        BigInt(message.data.fid),
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ])
  
      const challenged = await walletOptimisticVerifier.read.tryChallengeRemove([
        BigInt(message.data.fid),
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);
  
      expect(challenged).to.equal(true);
    });

    it("Invalid remove signature challenged until reward depleted", async function () {
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(deployFixture);

      const challengeArgs: [bigint, `0x${string}`, `0x${string}`, `0x${string}`][] = []

      for (let i = 0; i < 5; i++) {
        const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress(BigInt(i + 10));

        await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

        const encodedData = encodeAbiParameters(
          parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
          [
            toHexString(message.signature.subarray(0, 32)),
            toHexString(randomBytes(32)),
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

        challengeArgs.push([
          fid,
          alice.address, 
          toHexString(message.signer),
          encodedData
        ])
      }
  
      await time.increase(16400);

      for (let i = 0; i < 5; i++) {
        const challenged = await walletOptimisticVerifier.read.tryChallengeRemove(challengeArgs[i]);

        expect(challenged).to.equal(true);

        await walletOptimisticVerifier.write.challengeRemove(challengeArgs[i]);
      }

      await time.increase(86400);

      for (let i = 0; i < 5; i++) {
        await expect(walletOptimisticVerifier.read.verifyRemove(challengeArgs[i])).to.be.rejectedWith(`NotEnoughDeposit(0)`)
      }
    });

    it("Valid remove signature but invalid public key can't be submitted", async function () {
      const [ wallet1 ] = await hre.viem.getWalletClients()
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

      await expect(walletOptimisticVerifier.write.submitVerification([
        MessageType.VERIFICATION_REMOVE,
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ])).to.be.rejectedWith(`InvalidPublicKey(${fid}, "${toHexString(message.signer)}")`);

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

    it("Challenge add before submit", async () => {
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } =
        await signVerificationAddAddress();

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(randomBytes(32)),
          toHexString(messageBytes),
        ]
      );

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

      // Nothing happened...

      await walletOptimisticVerifier.write.submitVerification([
        MessageType.VERIFICATION_ADD_ETH_ADDRESS,
        fid,
        alice.address,
        toHexString(message.signer),
        encodedData,
      ]);
    })

    it("Challenge remove before submit", async () => {
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(deployFixture);
      const message = removeMessage;
      const messageBytes = removeMessageBytes;

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(randomBytes(32)),
          toHexString(messageBytes),
        ]
      );

      const challenged = await walletOptimisticVerifier.read.tryChallengeRemove([
        BigInt(message.data.fid),
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      expect(challenged).to.equal(true);

      await walletOptimisticVerifier.write.challengeRemove([
        BigInt(message.data.fid),
        toHexString(message.data.verificationRemoveBody.address),
        toHexString(message.signer),
        encodedData,
      ]);

      // Nothing happened...
    })

    it("Banned Relayer", async () => {
      const [ wallet1, wallet2 ] = await hre.viem.getWalletClients()
  
      // Add security role for self
      const { walletOptimisticVerifier, publicKeyVerifier } = await loadFixture(
        deployFixture
      );
  
      const SECURITY_ROLE = keccak256(Buffer.from("SECURITY_ROLE"));
      const RELAYER_ROLE = keccak256(Buffer.from("RELAYER_ROLE"));
  
      await walletOptimisticVerifier.write.grantRole([ RELAYER_ROLE, wallet2.account.address ])

      {
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
      }

      {
        const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress();

        await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

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
        ], { account: wallet2.account });
      }
  
      await expect(walletOptimisticVerifier.write.disableRelayer([ wallet2.account.address ])).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet1.account.address)}", "${SECURITY_ROLE}")`);
      
      await walletOptimisticVerifier.write.grantRole([ SECURITY_ROLE, wallet1.account.address ])
  
      await walletOptimisticVerifier.write.disableRelayer([ wallet2.account.address ])

      {
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
  
        await expect(walletOptimisticVerifier.write.submitVerification([
            MessageType.VERIFICATION_ADD_ETH_ADDRESS,
            BigInt(message.data.fid),
            toHexString(message.data.verificationAddAddressBody.address),
            toHexString(message.signer),
            encodedData,
          ], { account: wallet2.account })
        ).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet2.account.address)}", "${RELAYER_ROLE}")`);
      }

      {
        const { fid, alice, message, messageBytes } = await signVerificationRemoveAddress();

        const encodedData = encodeAbiParameters(
          parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
          [
            toHexString(message.signature.subarray(0, 32)),
            toHexString(message.signature.subarray(32)),
            toHexString(messageBytes),
          ]
        );
  
        await expect(
          walletOptimisticVerifier.write.submitVerification([
            MessageType.VERIFICATION_REMOVE,
            fid,
            alice.address,
            toHexString(message.signer),
            encodedData,
          ], { account: wallet2.account })
        ).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet2.account.address)}", "${RELAYER_ROLE}")`);
      }
    })

    it("Invalid message type", async () => {
      const { walletOptimisticVerifier } = await loadFixture(
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

      await expect(walletOptimisticVerifier.read.hash([
        9,
        fid,
        toHexString(message.data.verificationAddAddressBody.address),
        toHexString(message.signer),
        encodedData,
      ])).to.be.rejected
    })
  });

  describe("Router invalid cases", () => {
    it("Undefined method for verifying add", async () => {
      const { resolver, publicKeyVerifier } = await loadFixture(deployFixture);
      const { fid, alice, message, messageBytes } =
        await signVerificationAddAddress();

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      expect(
        await resolver.read.verifyAdd(
          [
            fid,
            alice.address,
            toHexString(message.signer),
            9999n,
            encodedData,
          ]
        )
      ).to.equal(false)
    })

    it("Invalid public key for verifying add", async () => {
      const { resolver } = await loadFixture(deployFixture);
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

      expect(
        await resolver.read.verifyAdd(
          [
            fid,
            alice.address,
            toHexString(message.signer),
            1n,
            encodedData,
          ]
        )
      ).to.equal(false)
    })

    it("Undefined method for verifying remove", async () => {
      const { resolver, publicKeyVerifier } = await loadFixture(deployFixture);
      const message = removeMessage;
      const messageBytes = removeMessageBytes;

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      expect(
        await resolver.read.verifyRemove(
          [
            BigInt(message.data.fid),
            toHexString(message.data.verificationRemoveBody.address),
            toHexString(message.signer),
            9999n,
            encodedData,
          ]
        )
      ).to.equal(false)
    })

    it("Invalid public key for verifying remove", async () => {
      const { resolver } = await loadFixture(deployFixture);
      const { message, messageBytes } = await signVerificationRemoveAddress();

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      expect(
        await resolver.read.verifyRemove(
          [
            BigInt(message.data.fid),
            toHexString(message.data.verificationRemoveBody.address),
            toHexString(message.signer),
            1n,
            encodedData,
          ]
        )
      ).to.equal(false)
    })

    it("No permission to add verifier", async () => {
      const [ _, wallet2 ] = await hre.viem.getWalletClients()
      const { resolver } = await loadFixture(deployFixture);

      const OPERATOR_ROLE = keccak256(Buffer.from("OPERATOR_ROLE"));

      await expect(resolver.write.setVerifier([3n, resolver.address], { account: wallet2.account })).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet2.account.address)}", "${OPERATOR_ROLE}")`)
      await expect(resolver.write.setPublicKeyVerifier([resolver.address], { account: wallet2.account })).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet2.account.address)}", "${OPERATOR_ROLE}")`)
    })

    it("Blacklist verifier", async () => {
      const [ wallet1 ] = await hre.viem.getWalletClients()
      const { resolver, publicKeyVerifier } = await loadFixture(deployFixture);

      const SECURITY_ROLE = keccak256(Buffer.from("SECURITY_ROLE"));

      const { fid, alice, message, messageBytes } =
        await signVerificationAddAddress();

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      expect(
        await resolver.read.verifyAdd(
          [
            fid,
            alice.address,
            toHexString(message.signer),
            1n,
            encodedData,
          ]
        )
      ).to.equal(true)
      
      await expect(resolver.write.emergencyRemoveVerifier([1n])).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet1.account.address)}", "${SECURITY_ROLE}")`)
    
      await resolver.write.grantRole([ SECURITY_ROLE, wallet1.account.address ])

      await resolver.write.emergencyRemoveVerifier([1n])

      expect(
        await resolver.read.verifyAdd(
          [
            fid,
            alice.address,
            toHexString(message.signer),
            1n,
            encodedData,
          ]
        )
      ).to.equal(false)
    })
  })

  describe("Resolver invalid cases", async () => {
    it("Revoke non-existence attestation", async () => {
      const { resolver } = await loadFixture(deployFixture);
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

      const { result } = await resolver.simulate.revoke([
        toHexString(message.data.verificationRemoveBody.address),
        BigInt(message.data.fid),
        toHexString(message.signer),
        1n,
        encodedData,
      ])

      expect(result).to.be.false
    })

    it("Can't attest to resolver directly with EOA wallet", async () => {
      const { resolver, eas } = await loadFixture(deployFixture);
      const { alice, message, messageBytes } =
        await signVerificationAddAddress();

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );
  
      await expect(
        eas.write.attest(
          [
            {
              schema: await resolver.read.schemaId(),
              data: {
                recipient: alice.address,
                expirationTime: 0n,
                revocable: true,
                value: 0n,
                refUID:
                  "0x0000000000000000000000000000000000000000000000000000000000000000",
                data: encodedData,
              },
            },
          ],
        )
      ).to.be.rejected;
    })

    it("Duplicated attestations", async () => {
      const { resolver, publicKeyVerifier } = await loadFixture(deployFixture);

      const { message, messageBytes } = await signVerificationAddAddress();

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      await publicKeyVerifier.write.addKey([ fid, toHexString(message.signer) ])

      await resolver.write.attest([
        toHexString(message.data.verificationAddAddressBody.address),
        fid,
        toHexString(message.signer),
        1n,
        encodedData,
      ]);

      await expect(
        resolver.write.attest([
          toHexString(message.data.verificationAddAddressBody.address),
          fid,
          toHexString(message.signer),
          1n,
          encodedData,
        ])
      ).to.be.rejected;
    })

    // These cases are impossible as there is no way to attest with different schema and attestor
    // Therefore, we only simulate these cases
    it("Simulate impossible attestations", async () => {
      const [ walletClient ] = await hre.viem.getWalletClients()
      const publicClient = await hre.viem.getPublicClient()

      const { resolver, eas, schemaRegistry } = await loadFixture(deployFixture);
      const { alice, message, messageBytes } =
        await signVerificationAddAddress();

      const encodedData = encodeAbiParameters(
        parseAbiParameters("bytes32 r, bytes32 s, bytes message"),
        [
          toHexString(message.signature.subarray(0, 32)),
          toHexString(message.signature.subarray(32)),
          toHexString(messageBytes),
        ]
      );

      await schemaRegistry.write.register([
        "bytes32 dummy",
        resolver.address,
        true,
      ]);
    
      const schemaId = keccak256(
        encodePacked(
          ["string", "address", "bool"],
          ["bytes32 dummy", resolver.address, true]
        )
      );

      const contract = getContract({
        address: resolver.address,
        abi: [
          {
            "inputs": [
              {
                "components": [
                  {
                    "internalType": "bytes32",
                    "name": "uid",
                    "type": "bytes32"
                  },
                  {
                    "internalType": "bytes32",
                    "name": "schema",
                    "type": "bytes32"
                  },
                  {
                    "internalType": "uint64",
                    "name": "time",
                    "type": "uint64"
                  },
                  {
                    "internalType": "uint64",
                    "name": "expirationTime",
                    "type": "uint64"
                  },
                  {
                    "internalType": "uint64",
                    "name": "revocationTime",
                    "type": "uint64"
                  },
                  {
                    "internalType": "bytes32",
                    "name": "refUID",
                    "type": "bytes32"
                  },
                  {
                    "internalType": "address",
                    "name": "recipient",
                    "type": "address"
                  },
                  {
                    "internalType": "address",
                    "name": "attester",
                    "type": "address"
                  },
                  {
                    "internalType": "bool",
                    "name": "revocable",
                    "type": "bool"
                  },
                  {
                    "internalType": "bytes",
                    "name": "data",
                    "type": "bytes"
                  }
                ],
                "internalType": "struct Attestation",
                "name": "attestation",
                "type": "tuple"
              }
            ],
            "name": "attest",
            "outputs": [
              {
                "internalType": "bool",
                "name": "",
                "type": "bool"
              }
            ],
            "stateMutability": "payable",
            "type": "function"
          },
          {
            "inputs": [
              {
                "components": [
                  {
                    "internalType": "bytes32",
                    "name": "uid",
                    "type": "bytes32"
                  },
                  {
                    "internalType": "bytes32",
                    "name": "schema",
                    "type": "bytes32"
                  },
                  {
                    "internalType": "uint64",
                    "name": "time",
                    "type": "uint64"
                  },
                  {
                    "internalType": "uint64",
                    "name": "expirationTime",
                    "type": "uint64"
                  },
                  {
                    "internalType": "uint64",
                    "name": "revocationTime",
                    "type": "uint64"
                  },
                  {
                    "internalType": "bytes32",
                    "name": "refUID",
                    "type": "bytes32"
                  },
                  {
                    "internalType": "address",
                    "name": "recipient",
                    "type": "address"
                  },
                  {
                    "internalType": "address",
                    "name": "attester",
                    "type": "address"
                  },
                  {
                    "internalType": "bool",
                    "name": "revocable",
                    "type": "bool"
                  },
                  {
                    "internalType": "bytes",
                    "name": "data",
                    "type": "bytes"
                  }
                ],
                "internalType": "struct Attestation",
                "name": "attestation",
                "type": "tuple"
              }
            ],
            "name": "revoke",
            "outputs": [
              {
                "internalType": "bool",
                "name": "",
                "type": "bool"
              }
            ],
            "stateMutability": "payable",
            "type": "function"
          },
        ],
        client: {
          public: publicClient,
          wallet: walletClient,
        },
      });

      await impersonateAccount("0x4200000000000000000000000000000000000021")
      const [easAccount] = await hre.viem.getWalletClients({account: "0x4200000000000000000000000000000000000021"})

      {
        const { result } = await contract.simulate.attest([
          {
            uid: '0x0000000000000000000000000000000000000000000000000000000000000000',
            attester: resolver.address,
            data: '0x0000000000000000000000000000000000000000000000000000000000000000',
            expirationTime: 0n,
            recipient: alice.address,
            refUID: '0x0000000000000000000000000000000000000000000000000000000000000000',
            revocable: true,
            revocationTime: 0n,
            schema: schemaId,
            time: 1000n,
          }
        ], {
          account: easAccount.account as any,
        })

        expect(result).to.be.false
      }

      {
        const { result } = await contract.simulate.revoke([
          {
            uid: '0x0000000000000000000000000000000000000000000000000000000000000000',
            attester: alice.address,
            data: '0x0000000000000000000000000000000000000000000000000000000000000000',
            expirationTime: 0n,
            recipient: alice.address,
            refUID: '0x0000000000000000000000000000000000000000000000000000000000000000',
            revocable: true,
            revocationTime: 0n,
            schema: schemaId,
            time: 1000n,
          }
        ], {
          account: easAccount.account as any,
        })

        expect(result).to.be.false
      }

      {
        const { result } = await contract.simulate.revoke([
          {
            uid: '0x0000000000000000000000000000000000000000000000000000000000000000',
            attester: resolver.address,
            data: '0x00',
            expirationTime: 0n,
            recipient: alice.address,
            refUID: '0x0000000000000000000000000000000000000000000000000000000000000000',
            revocable: true,
            revocationTime: 0n,
            schema: schemaId,
            time: 1000n,
          }
        ], {
          account: easAccount.account as any,
        })

        expect(result).to.be.false
      }
    })
  })
})
