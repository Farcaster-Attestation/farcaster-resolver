import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import { deployResolverWithAttestations } from "./utils";
import FarcasterMembershipModule from "../ignition/modules/FarcasterMembership";
import FarcasterResolverSimpleConsumerModule from "../ignition/modules/FarcasterResolverSimpleConsumer";
import { encodeAbiParameters, encodePacked, keccak256, parseAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";

async function deployFixture() {
  const result = await deployResolverWithAttestations();
  
  // Deploy the parent attestations
  await result.schemaRegistry.write.register([
    "uint256 fid",
    result.simpleConsumer.address,
    true,
  ]);

  const schemaId = keccak256(
    encodePacked(
      ["string", "address", "bool"],
      ["uint256 fid", result.simpleConsumer.address, true]
    )
  );

  const encodedData = encodeAbiParameters(
    parseAbiParameters("uint256 fid"),
    [
      1n,
    ]
  );

  expect(await result.resolver.read.isVerified([1n, result.alices[0].address])).to.equal(true)

  const publicClient = await hre.viem.getPublicClient();

  const hash = await result.eas.write.attest([
    {
      schema: schemaId,
      data: {
        recipient: result.simpleConsumer.address,
        expirationTime: 0n,
        revocable: true,
        value: 0n,
        refUID: "0x0000000000000000000000000000000000000000000000000000000000000000",
        data: encodedData,
      },
    },
  ], {
    account: result.alices[0],
  });
  
  const receipt = await publicClient.waitForTransactionReceipt({ hash })
  const uid = receipt.logs.find(log => log.topics[0] == '0x8bf46bf4cfd674fa735a3d63ec1c9ad4153f033c290341f3a588b75685141b35')!.data

  return {
    ...result,
    uid,
  };
}

describe("FarcasterMembership", function () {
  it("Super admin can add and remove admin/member", async function () {
    const { alices, membership, uid } = await loadFixture(deployFixture);
    
    expect(await membership.read.countMembers([uid])).to.equal(0n);
    expect(await membership.read.getMembers([uid])).to.deep.equal([]);
    expect(await membership.read.getMember([uid, 2n])).to.deep.equal([false, 0n]);
    expect(await membership.read.getMember([uid, 1n])).to.deep.equal([false, 0n]);

    expect(membership.write.setMember([uid, 3n, 2n, 0b1100000n], { account: alices[2] })).to.not.be.rejectedWith('PermissionDenied()');

    await membership.write.setMember([uid, 1n, 2n, 0b1100000n], { account: alices[0] });

    expect(membership.write.setMember([uid, 3n, 2n, 0b1100000n], { account: alices[2] })).to.not.be.rejectedWith('PermissionDenied()');

    expect(await membership.read.countMembers([uid])).to.equal(2n);
    expect(await membership.read.getMembers([uid])).to.deep.equal([{
      farcasterId: 1n,
      permissions: 0b1111111n,
    }, {
      farcasterId: 2n,
      permissions: 0b1100000n,
    }]);
    expect(await membership.read.getMember([uid, 1n])).to.deep.equal([true, 0b1111111n]);
    expect(await membership.read.getMember([uid, 2n])).to.deep.equal([true, 0b1100000n]);

    await membership.write.setMember([uid, 2n, 3n, 0b1011111n], { account: alices[1] });
    await membership.write.setMember([uid, 1n, 4n, 0b0111111n], { account: alices[0] });

    expect(await membership.read.countMembers([uid])).to.equal(4n);
    expect(await membership.read.getMembers([uid])).to.deep.equal([{
      farcasterId: 1n,
      permissions: 0b1111111n,
    }, {
      farcasterId: 2n,
      permissions: 0b1100000n,
    }, {
      farcasterId: 3n,
      permissions: 0b1011111n,
    }, {
      farcasterId: 4n,
      permissions: 0b0111111n,
    }]);
    expect(await membership.read.getMember([uid, 1n])).to.deep.equal([true, 0b1111111n]);
    expect(await membership.read.getMember([uid, 2n])).to.deep.equal([true, 0b1100000n]);
    expect(await membership.read.getMember([uid, 3n])).to.deep.equal([true, 0b1011111n]);
    expect(await membership.read.getMember([uid, 4n])).to.deep.equal([true, 0b0111111n]);

    await expect(membership.write.removeMember([uid, 3n, 1n], { account: alices[0] })).to.be.rejectedWith('PermissionDenied')
    await membership.write.removeMember([uid, 3n, 1n], { account: alices[2] });
    await expect(membership.write.removeMember([uid, 3n, 1n], { account: alices[2] })).to.be.rejectedWith('PermissionDenied')
    await expect(membership.write.removeMember([uid, 4n, 1n], { account: alices[3] })).to.be.rejectedWith('PermissionDenied')

    expect(await membership.read.countMembers([uid])).to.equal(3n);
    expect(await membership.read.getMembers([uid])).to.deep.equal([{
      farcasterId: 4n,
      permissions: 0b0111111n,
    }, {
      farcasterId: 2n,
      permissions: 0b1100000n,
    }, {
      farcasterId: 3n,
      permissions: 0b1011111n,
    }]);
    expect(await membership.read.getMember([uid, 1n])).to.deep.equal([false, 0n]);
    expect(await membership.read.getMember([uid, 2n])).to.deep.equal([true, 0b1100000n]);
    expect(await membership.read.getMember([uid, 3n])).to.deep.equal([true, 0b1011111n]);
    expect(await membership.read.getMember([uid, 4n])).to.deep.equal([true, 0b0111111n]);
  });

  it("Admin can add and remove member", async function () {
    const { alices, membership, uid } = await loadFixture(deployFixture);

    // Setup initial members
    await membership.write.setMember([uid, 1n, 2n, 0b1111111n], { account: alices[0] }); // Super admin
    await membership.write.setMember([uid, 2n, 3n, 0b0011111n], { account: alices[1] }); // Admin

    // Admin can add regular member
    await membership.write.setMember([uid, 3n, 4n, 0b0000111n], { account: alices[2] });
    expect(await membership.read.getMember([uid, 4n])).to.deep.equal([true, 0b0000111n]);

    // Admin can remove regular member 
    await membership.write.removeMember([uid, 3n, 4n], { account: alices[2] });
    expect(await membership.read.getMember([uid, 4n])).to.deep.equal([false, 0n]);
  });

  it("Admin can't add or remove super admin", async function () {
    const { alices, membership, uid } = await loadFixture(deployFixture);

    // Setup initial members
    await membership.write.setMember([uid, 1n, 2n, 0b1111111n], { account: alices[0] }); // Super admin
    await membership.write.setMember([uid, 2n, 3n, 0b0011111n], { account: alices[1] }); // Admin

    // Admin can't add super admin
    await expect(membership.write.setMember(
      [uid, 3n, 4n, 0b1111111n], 
      { account: alices[2] }
    )).to.be.rejectedWith('PermissionDenied');

    // Admin can't remove super admin
    await expect(membership.write.removeMember(
      [uid, 3n, 2n],
      { account: alices[2] }
    )).to.be.rejectedWith('PermissionDenied');
  });

  it("Member can't add or remove admin", async function () {
    const { alices, membership, uid } = await loadFixture(deployFixture);

    // Setup initial members
    await membership.write.setMember([uid, 1n, 2n, 0b1111111n], { account: alices[0] }); // Super admin
    await membership.write.setMember([uid, 2n, 3n, 0b0011111n], { account: alices[1] }); // Admin
    await expect(membership.write.setMember([uid, 3n, 4n, 0b0010111n], { account: alices[2] })).to.be.rejectedWith('PermissionDenied');
    await expect(membership.write.setMember([uid, 3n, 4n, 0b0001111n], { account: alices[2] })).to.be.rejectedWith('PermissionDenied');
    await membership.write.setMember([uid, 3n, 4n, 0b0000111n], { account: alices[2] }); // Member

    // Member can't add admin
    await expect(membership.write.setMember(
      [uid, 4n, 5n, 0b0011111n],
      { account: alices[3] }
    )).to.be.rejectedWith('PermissionDenied');

    // Member can't add super admin
    await expect(membership.write.setMember(
      [uid, 4n, 5n, 0b1111111n],
      { account: alices[3] }
    )).to.be.rejectedWith('PermissionDenied');

    // Member can't remove admin
    await expect(membership.write.removeMember(
      [uid, 4n, 3n],
      { account: alices[3] }
    )).to.be.rejectedWith('PermissionDenied');

    // Member can't remove super admin
    await expect(membership.write.removeMember(
      [uid, 4n, 2n],
      { account: alices[3] }
    )).to.be.rejectedWith('PermissionDenied');
  });

  it("Leave permission", async function () {
    const { alices, membership, uid } = await loadFixture(deployFixture);

    await membership.write.setMember([uid, 1n, 2n, 0b1111111n], { account: alices[0] });
    await membership.write.setMember([uid, 2n, 3n, 0b1111011n], { account: alices[1] });

    // FID 2 leaves
    await membership.write.removeMember([uid, 2n, 2n], { account: alices[1] });

    // FID 3 can't leave
    expect(membership.write.removeMember([uid, 3n, 3n], { account: alices[2] })).to.be.rejectedWith('PermissionDenied()');

    expect(await membership.read.countMembers([uid])).to.equal(2n);
    expect(await membership.read.getMember([uid, 2n])).to.deep.equal([false, 0n]);
  });

  it("Add / remove member permission", async function () {
    const { alices, membership, uid } = await loadFixture(deployFixture);

    for (let i = 0; i < 0b1111; i++) {
      
    }
  });
});
