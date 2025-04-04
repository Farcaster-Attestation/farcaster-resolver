import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { expect } from "chai";
import hre, { ignition } from "hardhat";
import FarcasterResolverInteropModule from "../ignition/modules/FarcasterResolverInterop";

async function deployFixture() {
  return ignition.deploy(FarcasterResolverInteropModule);
}

describe("FarcasterResolverInterop", () => {
  it("Can cross chain sync", async () => {
    const { interop, resolver } = await loadFixture(deployFixture);

    const publicClient = await hre.viem.getPublicClient();

    expect(await interop.read.isSourceChain()).to.equal(true);

    const [wallet] = await hre.viem.getWalletClients();
    const walletAddress = wallet.account.address;

    // We can't interop here as it's not launched
    await expect(
      interop.write.crossChainSync([420n, walletAddress, 1n])
    ).to.be.rejectedWith("Proxy: implementation not initialized");
  });

  it("Prevent smart contract wallet from crossChainSync", async () => {
    const { interop } = await loadFixture(deployFixture);

    const maliciousWallet = await hre.viem.deployContract(
      "MaliciousSmartWallet"
    );

    await expect(
      interop.write.crossChainSync([420n, maliciousWallet.address, 1n])
    ).to.be.rejectedWith("SmartContractWalletNotAllowed");
  });

  it("Can attest with smart contract wallet after allowed", async () => {
    const { interop } = await loadFixture(deployFixture);

    const maliciousWallet = await hre.viem.deployContract(
      "MaliciousSmartWallet"
    );

    // Enable interop for the smart contract wallet
    await maliciousWallet.write.enableInterop([interop.address, 420n]);

    // We can't interop here as it's not launched
    await expect(
      interop.write.crossChainSync([420n, maliciousWallet.address, 1n])
    ).to.be.rejectedWith("Proxy: implementation not initialized");
  });
});
