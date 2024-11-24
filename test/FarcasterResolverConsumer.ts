import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import { deployResolverWithAttestations, getAttestationUid } from "./utils";
import FarcasterMembershipModule from "../ignition/modules/FarcasterMembership";
import FarcasterResolverSimpleConsumerModule from "../ignition/modules/FarcasterResolverSimpleConsumer";
import {
  encodeAbiParameters,
  encodePacked,
  keccak256,
  parseAbiParameters,
  PrivateKeyAccount,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

async function deploySimpleSchema(
  schemaRegistry: any,
  consumer: `0x${string}`
) {
  await schemaRegistry.write.register(["uint256 fid", consumer, true]);

  const schemaId = keccak256(
    encodePacked(["string", "address", "bool"], ["uint256 fid", consumer, true])
  );

  return schemaId;
}

async function deployStandardSchema(
  schemaRegistry: any,
  consumer: `0x${string}`
) {
  await schemaRegistry.write.register([
    "bytes32 dummy,uint256 fid,bytes32 refUID",
    consumer,
    true,
  ]);

  const schemaId = keccak256(
    encodePacked(
      ["string", "address", "bool"],
      ["bytes32 dummy,uint256 fid,bytes32 refUID", consumer, true]
    )
  );

  return schemaId;
}

async function deploySimpleFixture() {
  const result = await deployResolverWithAttestations();

  expect(
    await result.resolver.read.isVerified([1n, result.alices[0].address])
  ).to.equal(true);

  return {
    ...result,
    schemaId: await deploySimpleSchema(
      result.schemaRegistry,
      result.simpleConsumer.address
    ),
  };
}

async function attestSimpleSchema(
  eas: any,
  consumer: `0x${string}`,
  alice: PrivateKeyAccount,
  fid: bigint
) {
  const encodedData = encodeAbiParameters(parseAbiParameters("uint256 fid"), [
    fid,
  ]);

  const publicClient = await hre.viem.getPublicClient();

  const schemaId = keccak256(
    encodePacked(["string", "address", "bool"], ["uint256 fid", consumer, true])
  );

  const hash = await eas.write.attest(
    [
      {
        schema: schemaId,
        data: {
          recipient: consumer,
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
      account: alice,
    }
  );

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const uid = receipt.logs.find(
    (log) =>
      log.topics[0] ==
      "0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35"
  )!.data;

  return uid;
}

describe("SimpleConsumer", function () {
  it("Valid", async function () {
    const { eas, schemaId, alices, simpleConsumer } = await loadFixture(
      deploySimpleFixture
    );

    const encodedData = encodeAbiParameters(parseAbiParameters("uint256 fid"), [
      1n,
    ]);

    await eas.write.attest(
      [
        {
          schema: schemaId,
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
        account: alices[0],
      }
    );
  });

  it("Invalid FID", async function () {
    const { eas, schemaId, alices, simpleConsumer } = await loadFixture(
      deploySimpleFixture
    );

    const encodedData = encodeAbiParameters(parseAbiParameters("uint256 fid"), [
      2n,
    ]);

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
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
          account: alices[0],
        }
      )
    ).to.be.rejected;
  });

  it("Invalid attester", async function () {
    const { eas, schemaId, alices, simpleConsumer } = await loadFixture(
      deploySimpleFixture
    );

    const encodedData = encodeAbiParameters(parseAbiParameters("uint256 fid"), [
      1n,
    ]);

    expect(
      eas.write.attest([
        {
          schema: schemaId,
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
      ])
    ).to.be.rejected;
  });
});

describe("StandardConsumer", function () {
  it("No Ref", async function () {
    const { eas, resolver, membership, schemaRegistry, alices } =
      await loadFixture(deploySimpleFixture);

    const standardConsumer = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        eas.address,
        resolver.address,
        membership.address,
        false,
        false,
        false,
        false,
        32n,
        0n,
      ]
    );

    const schemaId = await deployStandardSchema(
      schemaRegistry,
      standardConsumer.address
    );

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        1n,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      ]
    );

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
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
      )
    ).to.be.rejected;

    const uid = await getAttestationUid(await eas.write.attest(
      [
        {
          schema: schemaId,
          data: {
            recipient: standardConsumer.address,
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
        account: alices[0],
        }
      )
    );

    expect(
      eas.write.revoke(
        [
          {
            schema: schemaId,
            data: {
              uid,
              value: 0n,
            },
          },
        ],
        { account: alices[3] }
      )
    ).to.be.rejected;

    await eas.write.revoke([
      {
        schema: schemaId,
        data: {
          uid,
          value: 0n,
        },
      },
    ], { account: alices[0] });
  });

  it("No Ref + Recipient", async function () {
    const { eas, resolver, membership, schemaRegistry, alices } =
      await loadFixture(deploySimpleFixture);

    const standardConsumer = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        eas.address,
        resolver.address,
        membership.address,
        true,
        false,
        false,
        false,
        32n,
        0n,
      ]
    );

    const schemaId = await deployStandardSchema(
      schemaRegistry,
      standardConsumer.address
    );

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        1n,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      ]
    );

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
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
      )
    ).to.be.rejected;

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
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
          account: alices[0],
        }
      )
    ).to.be.rejected;

    const uid = await getAttestationUid(
      await eas.write.attest([
        {
          schema: schemaId,
          data: {
            recipient: alices[0].address,
            expirationTime: 0n,
            revocable: true,
            refUID:
              "0x0000000000000000000000000000000000000000000000000000000000000000",
            data: encodedData,
            value: 0n,
          },
        },
      ])
    );

    expect(
      eas.write.revoke(
        [
          {
            schema: schemaId,
            data: {
              uid,
              value: 0n,
            },
          },
        ],
        { account: alices[3] }
      )
    ).to.be.rejected;

    await eas.write.revoke([
      {
        schema: schemaId,
        data: {
          uid,
          value: 0n,
        },
      },
    ]);
  });

  it("Basic Ref", async function () {
    const {
      eas,
      resolver,
      membership,
      schemaRegistry,
      alices,
      simpleConsumer,
    } = await loadFixture(deploySimpleFixture);

    const uid = await attestSimpleSchema(
      eas,
      simpleConsumer.address,
      alices[0],
      1n
    );

    const standardConsumer = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        eas.address,
        resolver.address,
        membership.address,
        false,
        true,
        false,
        false,
        32n,
        0n,
      ]
    );

    const schemaId = await deployStandardSchema(
      schemaRegistry,
      standardConsumer.address
    );

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        1n,
        uid,
      ]
    );

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
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
          account: alices[0],
        }
      )
    ).to.be.rejected;

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
              expirationTime: 0n,
              revocable: true,
              refUID: uid,
              data: encodedData,
              value: 0n,
            },
          },
        ],
        {
          account: alices[1],
        }
      )
    ).to.be.rejected;

    const attUid = await getAttestationUid(await eas.write.attest(
      [
        {
          schema: schemaId,
          data: {
            recipient: standardConsumer.address,
            expirationTime: 0n,
            revocable: true,
            refUID: uid,
            data: encodedData,
            value: 0n,
          },
        },
      ],
      {
        account: alices[0],
        }
      )
    );

    expect(
      eas.write.revoke(
        [
          {
            schema: schemaId,
            data: {
              uid: attUid,
              value: 0n,
            },
          },
        ],
        { account: alices[3] }
      )
    ).to.be.rejected;

    await eas.write.revoke([
      {
        schema: schemaId,
        data: {
          uid: attUid,
          value: 0n,
        },
      },
    ], { account: alices[0] });
  });

  it("Basic Ref in body", async function () {
    const {
      eas,
      resolver,
      membership,
      schemaRegistry,
      alices,
      simpleConsumer,
    } = await loadFixture(deploySimpleFixture);

    const uid = await attestSimpleSchema(
      eas,
      simpleConsumer.address,
      alices[0],
      1n
    );

    const standardConsumer = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        eas.address,
        resolver.address,
        membership.address,
        false,
        true,
        false,
        true,
        32n,
        64n,
      ]
    );

    const schemaId = await deployStandardSchema(
      schemaRegistry,
      standardConsumer.address
    );

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        1n,
        uid,
      ]
    );

    const encodedDataNoRef = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        1n,
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      ]
    );

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
              expirationTime: 0n,
              revocable: true,
              refUID: uid,
              data: encodedDataNoRef,
              value: 0n,
            },
          },
        ],
        {
          account: alices[0],
        }
      )
    ).to.be.rejected;

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
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
      )
    ).to.be.rejected;

    const attUid = await getAttestationUid(
      await eas.write.attest(
        [
          {
          schema: schemaId,
          data: {
            recipient: standardConsumer.address,
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
        account: alices[0],
        }
      )
    );

    expect(
      eas.write.revoke(
        [
          {
            schema: schemaId,
            data: {
              uid: attUid,
              value: 0n,
            },
          },
        ],
        { account: alices[3] }
      )
    ).to.be.rejected;

    await eas.write.revoke([
      {
        schema: schemaId,
        data: {
          uid: attUid,
          value: 0n,
        },
      },
    ], { account: alices[0] });
  });

  it("Nested Ref", async function () {
    const {
      eas,
      resolver,
      membership,
      schemaRegistry,
      alices,
      simpleConsumer,
    } = await loadFixture(deploySimpleFixture);

    await schemaRegistry.write.register([
      "bytes32 dummy",
      "0x0000000000000000000000000000000000000000",
      true,
    ]);

    const dummySchemaId = keccak256(
      encodePacked(
        ["string", "address", "bool"],
        ["bytes32 dummy", "0x0000000000000000000000000000000000000000", true]
      )
    );

    const uid2 = await attestSimpleSchema(
      eas,
      simpleConsumer.address,
      alices[0],
      1n
    );

    const publicClient = await hre.viem.getPublicClient();

    const dummyEncodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy"),
      ["0x0000000000000000000000000000000000000000000000000000000000001234"]
    );

    const hash = await eas.write.attest([
      {
        schema: dummySchemaId,
        data: {
          recipient: "0x0000000000000000000000000000000000000000",
          expirationTime: 0n,
          revocable: true,
          value: 0n,
          refUID: uid2,
          data: dummyEncodedData,
        },
      },
    ]);

    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const uid = receipt.logs.find(
      (log) =>
        log.topics[0] ==
        "0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35"
    )!.data;

    const standardConsumer = await hre.viem.deployContract(
      "FarcasterResolverStandardConsumer",
      [
        eas.address,
        resolver.address,
        membership.address,
        false,
        true,
        false,
        false,
        32n,
        0n,
      ]
    );

    const schemaId = await deployStandardSchema(
      schemaRegistry,
      standardConsumer.address
    );

    const encodedData = encodeAbiParameters(
      parseAbiParameters("bytes32 dummy,uint256 fid,bytes32 refUID"),
      [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        1n,
        uid,
      ]
    );

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
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
          account: alices[0],
        }
      )
    ).to.be.rejected;

    expect(
      eas.write.attest(
        [
          {
            schema: schemaId,
            data: {
              recipient: standardConsumer.address,
              expirationTime: 0n,
              revocable: true,
              refUID: uid,
              data: encodedData,
              value: 0n,
            },
          },
        ],
        {
          account: alices[1],
        }
      )
    ).to.be.rejected;

    const attUid = await getAttestationUid(await eas.write.attest(
      [
        {
          schema: schemaId,
          data: {
            recipient: standardConsumer.address,
            expirationTime: 0n,
            revocable: true,
            refUID: uid,
            data: encodedData,
            value: 0n,
          },
        },
      ],
      {
        account: alices[0],
      }
    ));

    expect(
      eas.write.revoke(
        [
          {
            schema: schemaId,
            data: {
              uid: attUid,
              value: 0n,
            },
          },
        ],
        { account: alices[3] }
      )
    ).to.be.rejected;

    await eas.write.revoke([
      {
        schema: schemaId,
        data: {
          uid: attUid,
          value: 0n,
        },
      },
    ], { account: alices[0] });
  });
});
