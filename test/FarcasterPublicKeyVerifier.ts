import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import FarcasterResolverModule from "../ignition/modules/FarcasterResolver";

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
});
