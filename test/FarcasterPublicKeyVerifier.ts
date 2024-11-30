import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import FarcasterResolverModule from "../ignition/modules/FarcasterResolver";
import { getAddress, keccak256 } from "viem";

async function deployFixture() {
  return ignition.deploy(FarcasterResolverModule);
}

describe("FarcasterPublicKeyVerifier", function () {
  it("Valid public key", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    expect(await publicKeyVerifier.read.verifyPublicKey([328679n, '0xbb77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(true);
  });

  it("Removed key", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    expect(await publicKeyVerifier.read.verifyPublicKey([3346n, '0xffa82f02bb8fb56ccac3329c1854d36f2967245e7edd1ba60718639e36351248'])).to.equal(false);
  });

  it("Invalid FID", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    expect(await publicKeyVerifier.read.verifyPublicKey([100000000n, '0xbb77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  });

  it("Invalid public key", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    expect(await publicKeyVerifier.read.verifyPublicKey([328679n, '0xab77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  });

  it("Invalid both", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    expect(await publicKeyVerifier.read.verifyPublicKey([100000000n, '0xab77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  });

  it("Add key", async function () {
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    expect(await publicKeyVerifier.read.verifyPublicKey([328680n, '0xcc77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);

    await publicKeyVerifier.write.addKey([328680n, '0xcc77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a']);

    expect(await publicKeyVerifier.read.verifyPublicKey([328680n, '0xcc77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(true);
  });

  it("Non-operator can't add key", async function () {
    const [ _, wallet2 ] = await hre.viem.getWalletClients()
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    const OPERATOR_ROLE = keccak256(Buffer.from("OPERATOR_ROLE"));

    expect(await publicKeyVerifier.read.verifyPublicKey([328681n, '0xdd77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);

    await expect(
      publicKeyVerifier.write.addKey([328681n, '0xdd77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'], { account: wallet2.account })
    ).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet2.account.address)}", "${OPERATOR_ROLE}")`);

    expect(await publicKeyVerifier.read.verifyPublicKey([328681n, '0xdd77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  });

  it("Blacklist operator", async function () {
    const [ wallet1, wallet2 ] = await hre.viem.getWalletClients()
    const { publicKeyVerifier } = await loadFixture(deployFixture);

    const SECURITY_ROLE = keccak256(Buffer.from("SECURITY_ROLE"));
    const OPERATOR_ROLE = keccak256(Buffer.from("OPERATOR_ROLE"));

    await publicKeyVerifier.write.grantRole([ OPERATOR_ROLE, wallet2.account.address ])

    await expect(publicKeyVerifier.write.blacklistOperator([ wallet2.account.address ])).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet1.account.address)}", "${SECURITY_ROLE}")`);

    await publicKeyVerifier.write.addKey([328680n, '0xcc77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'], { account: wallet2.account });

    expect(await publicKeyVerifier.read.verifyPublicKey([328680n, '0xcc77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(true);

    await publicKeyVerifier.write.grantRole([ SECURITY_ROLE, wallet1.account.address ])

    await publicKeyVerifier.write.blacklistOperator([ wallet2.account.address ])

    await expect(publicKeyVerifier.write.addKey([328681n, '0xdd77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'], { account: wallet2.account })).to.be.rejectedWith(`AccessControlUnauthorizedAccount("${getAddress(wallet2.account.address)}", "${OPERATOR_ROLE}")`);
  
    expect(await publicKeyVerifier.read.verifyPublicKey([328681n, '0xdd77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a'])).to.equal(false);
  });
});
