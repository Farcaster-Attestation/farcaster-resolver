import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import { deployResolverWithAttestations, getAttestationUid } from "./utils";
import {
  encodeAbiParameters,
  encodePacked,
  keccak256,
  parseAbiParameters,
  PrivateKeyAccount,
} from "viem";

describe("FarcasterResolverStandardConsumer", function () {
  async function deployStandardConsumerFixture() {
    const result = await deployResolverWithAttestations();

    // Deploy MockPublicKeyVerifier and MockWalletVerifier
    const mockPublicKeyVerifier = await hre.viem.deployContract(
      "MockPublicKeyVerifier"
    );
    await mockPublicKeyVerifier.write.setReturnValue([true]);

    const mockWalletVerifier = await hre.viem.deployContract(
      "MockWalletVerifier"
    );
    await mockWalletVerifier.write.setReturnValue([true]);

    // Set the mock verifiers in the resolver
    await result.resolver.write.setPublicKeyVerifier([
      mockPublicKeyVerifier.address,
    ]);
    await result.resolver.write.setVerifier([1n, mockWalletVerifier.address]);

    // Verify that Alice's address is verified
    expect(
      await result.resolver.read.isVerified([1n, result.alices[0].address])
    ).to.equal(true);

    // Deploy the standard consumer
    const standardConsumer = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        result.eas.address,
        result.resolver.address,
        result.membership.address,
        false, // useRecipient
        true, // useRefFid
        false, // useRefCheck
        true, // useRefBody
        0n, // fidOffset
        32n, // refOffset
      ]
    );

    // Register schemas
    const standardConsumerSchemaId = await result.schemaRegistry.write.register(
      ["uint256 fid,bytes32 refUID", standardConsumer.address, true]
    );

    const nonResolverSchemaId = await result.schemaRegistry.write.register([
      "uint256 fid,bytes32 refUID",
      "0x0000000000000000000000000000000000000000",
      true,
    ]);

    // Register schema for simple consumer
    const simpleConsumerSchemaId = keccak256(
      encodePacked(
        ["string", "address", "bool"],
        ["uint256 fid", result.simpleConsumer.address, true]
      )
    );

    return {
      ...result,
      standardConsumer,
      standardConsumerSchemaId,
      nonResolverSchemaId,
      simpleConsumerSchemaId,
    };
  }

  async function deployStandardConsumerWithMembershipFixture() {
    const result = await deployStandardConsumerFixture();

    // Deploy a standard consumer with membership checking
    const standardConsumerWithMembership = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        result.eas.address,
        result.resolver.address,
        result.membership.address,
        false, // useRecipient
        false, // useRefFid
        true, // useRefCheck
        false, // useRefBody
        32n, // fidOffset
        0n, // refOffset
      ]
    );

    // Register schema for the consumer with membership
    const membershipConsumerSchemaId =
      await result.schemaRegistry.write.register([
        "bytes32 dummy,uint256 fid,bytes32 refUID",
        standardConsumerWithMembership.address,
        true,
      ]);

    return {
      ...result,
      standardConsumerWithMembership,
      membershipConsumerSchemaId,
    };
  }

  async function attestInSimpleConsumer(
    eas: any,
    simpleConsumer: any,
    simpleConsumerSchemaId: `0x${string}`,
    user: PrivateKeyAccount,
    fid: bigint
  ) {
    const encodedData = encodeAbiParameters(parseAbiParameters("uint256 fid"), [
      fid,
    ]);

    const hash = await eas.write.attest(
      [
        {
          schema: simpleConsumerSchemaId,
          data: {
            recipient: simpleConsumer.address,
            expirationTime: 0n,
            revocable: true,
            value: 0n,
            refUID:
              "0x0000000000000000000000000000000000000000000000000000000000000000",
            data: encodedData,
          },
        },
      ],
      {
        account: user,
      }
    );

    return await getAttestationUid(hash);
  }

  it("Should support decoder interfaces", async function () {
    const { standardConsumer } = await loadFixture(
      deployStandardConsumerFixture
    );

    // Check if the consumer supports the required interfaces
    expect(await standardConsumer.read.supportsInterface(["0xbe3efb08"])).to.be
      .true;
    expect(await standardConsumer.read.supportsInterface(["0xfafec1c7"])).to.be
      .true;
    expect(await standardConsumer.read.supportsInterface(["0x01ffc9a7"])).to.be
      .true;
    expect(await standardConsumer.read.supportsInterface(["0x96e8ee7c"])).to.be
      .true;
  });

  it("Should handle nested attestation with ref body", async function () {
    const {
      eas,
      resolver,
      simpleConsumer,
      standardConsumer,
      standardConsumerSchemaId,
      nonResolverSchemaId,
      simpleConsumerSchemaId,
      alices,
    } = await loadFixture(deployStandardConsumerFixture);

    const fid = 1000n;

    // Attest in the simple consumer
    await resolver.write.attest([
      alices[0].address,
      fid,
      "0x0100000000000000000000000000000000000000000000000000000000000000",
      1n,
      "0x",
    ]);

    const refAttestUid = await attestInSimpleConsumer(
      eas,
      simpleConsumer,
      simpleConsumerSchemaId,
      alices[0],
      fid
    );

    // Attest for Bob
    await resolver.write.attest([
      alices[1].address,
      fid,
      "0x0100000000000000000000000000000000000000000000000000000000000000",
      1n,
      "0x",
    ]);

    // Create an attestation with non-resolver schema
    const encodedData = encodeAbiParameters(
      parseAbiParameters("uint256 fid,bytes32 refUID"),
      [fid, refAttestUid]
    );

    const hash = await eas.write.attest(
      [
        {
          schema: nonResolverSchemaId,
          data: {
            recipient: alices[1].address,
            expirationTime: 0n,
            revocable: true,
            refUID:
              "0x0000000000000000000000000000000000000000000000000000000000000000",
            data: encodedData,
            value: 0n,
          },
        },
      ],
      {
        account: alices[1],
      }
    );

    const refAttestUid1 = await getAttestationUid(hash);

    // Attempt to create a nested attestation - should fail with MissingFarcasterResolverConsumer
    await expect(
      eas.write.attest(
        [
          {
            schema: standardConsumerSchemaId,
            data: {
              recipient: alices[1].address,
              expirationTime: 0n,
              revocable: true,
              refUID:
                "0x0000000000000000000000000000000000000000000000000000000000000000",
              data: encodeAbiParameters(
                parseAbiParameters("uint256 fid,bytes32 refUID"),
                [fid, refAttestUid1]
              ),
              value: 0n,
            },
          },
        ],
        {
          account: alices[1],
        }
      )
    ).to.be.rejectedWith(
      `MissingFarcasterResolverConsumer("${refAttestUid1}")`
    );
  });

  it("Should handle revoked attestations", async function () {
    const {
      eas,
      resolver,
      simpleConsumer,
      standardConsumer,
      standardConsumerSchemaId,
      simpleConsumerSchemaId,
      alices,
    } = await loadFixture(deployStandardConsumerFixture);

    const fid = 1000n;

    // Attest in the simple consumer
    await resolver.write.attest([
      alices[0].address,
      fid,
      "0x0100000000000000000000000000000000000000000000000000000000000000",
      1n,
      "0x",
    ]);

    const refAttestUid = await attestInSimpleConsumer(
      eas,
      simpleConsumer,
      simpleConsumerSchemaId,
      alices[0],
      fid
    );

    // Revoke the reference attestation
    await eas.write.revoke(
      [
        {
          schema: simpleConsumerSchemaId,
          data: {
            uid: refAttestUid,
            value: 0n,
          },
        },
      ],
      { account: alices[0] }
    );

    // Attempt to create an attestation with a revoked reference - should fail
    await expect(
      eas.write.attest(
        [
          {
            schema: standardConsumerSchemaId,
            data: {
              recipient: standardConsumer.address,
              expirationTime: 0n,
              revocable: true,
              refUID: refAttestUid,
              data: encodeAbiParameters(
                parseAbiParameters("uint256 fid,bytes32 refUID"),
                [fid, refAttestUid]
              ),
              value: 0n,
            },
          },
        ],
        {
          account: alices[0],
        }
      )
    ).to.be.rejectedWith(`AttestationRevoked("${refAttestUid}")`);
  });

  it("Should handle membership checking", async function () {
    const {
      eas,
      resolver,
      membership,
      simpleConsumer,
      standardConsumerWithMembership,
      membershipConsumerSchemaId,
      simpleConsumerSchemaId,
      alices,
    } = await loadFixture(deployStandardConsumerWithMembershipFixture);

    const fid = 1000n;

    // Attest in the simple consumer
    await resolver.write.attest([
      alices[0].address,
      fid,
      "0x0100000000000000000000000000000000000000000000000000000000000000",
      1n,
      "0x",
    ]);

    const refAttestUid = await attestInSimpleConsumer(
      eas,
      simpleConsumer,
      simpleConsumerSchemaId,
      alices[0],
      fid
    );

    // Add members with different permissions
    // FID 1: Both attest and revoke (0b11)
    // FID 2: Attest only (0b01)
    // FID 3: Revoke only (0b10)
    await membership.write.setMember([refAttestUid, 1n, 1n, 0b11n], {
      account: alices[0],
    });
    await membership.write.setMember([refAttestUid, 1n, 2n, 0b01n], {
      account: alices[0],
    });
    await membership.write.setMember([refAttestUid, 1n, 3n, 0b10n], {
      account: alices[0],
    });

    // Verify membership permissions
    expect(
      (await membership.simulate.verifyMember([refAttestUid, 1n, 0b01n])).result
    ).to.be.true;
    expect(
      (await membership.simulate.verifyMember([refAttestUid, 1n, 0b10n])).result
    ).to.be.true;
    expect(
      (await membership.simulate.verifyMember([refAttestUid, 2n, 0b01n])).result
    ).to.be.true;
    expect(
      (await membership.simulate.verifyMember([refAttestUid, 3n, 0b10n])).result
    ).to.be.true;

    // Helper function to create attestation data
    function createAttestationData(fid: bigint) {
      return encodeAbiParameters(
        parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
        [
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          fid,
          refAttestUid,
        ]
      );
    }

    // Test attestation with FID 1 (has both permissions)
    const attestUid1 = await getAttestationUid(
      await eas.write.attest(
        [
          {
            schema: membershipConsumerSchemaId,
            data: {
              recipient: standardConsumerWithMembership.address,
              expirationTime: 0n,
              revocable: true,
              refUID: refAttestUid,
              data: createAttestationData(1n),
              value: 0n,
            },
          },
        ],
        {
          account: alices[0],
        }
      )
    );

    // FID 1 can revoke their own attestation
    await eas.write.revoke(
      [
        {
          schema: membershipConsumerSchemaId,
          data: {
            uid: attestUid1,
            value: 0n,
          },
        },
      ],
      { account: alices[0] }
    );

    // Test attestation with FID 2 (attest only)
    const attestUid2 = await getAttestationUid(
      await eas.write.attest(
        [
          {
            schema: membershipConsumerSchemaId,
            data: {
              recipient: standardConsumerWithMembership.address,
              expirationTime: 0n,
              revocable: true,
              refUID: refAttestUid,
              data: createAttestationData(2n),
              value: 0n,
            },
          },
        ],
        {
          account: alices[1],
        }
      )
    );

    // FID 2 cannot revoke their attestation (no revoke permission)
    await expect(
      eas.write.revoke(
        [
          {
            schema: membershipConsumerSchemaId,
            data: {
              uid: attestUid2,
              value: 0n,
            },
          },
        ],
        { account: alices[1] }
      )
    ).to.be.rejected;

    // FID 3 cannot attest (no attest permission)
    await expect(
      eas.write.attest(
        [
          {
            schema: membershipConsumerSchemaId,
            data: {
              recipient: standardConsumerWithMembership.address,
              expirationTime: 0n,
              revocable: true,
              refUID: refAttestUid,
              data: createAttestationData(3n),
              value: 0n,
            },
          },
        ],
        {
          account: alices[2],
        }
      )
    ).to.be.rejected;

    // But FID 3 can revoke attestations (has revoke permission)
    await eas.write.revoke(
      [
        {
          schema: membershipConsumerSchemaId,
          data: {
            uid: attestUid2,
            value: 0n,
          },
        },
      ],
      { account: alices[2] }
    );
  });
});
