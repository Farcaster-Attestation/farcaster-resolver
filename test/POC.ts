import { loadFixture } from "@nomicfoundation/hardhat-toolbox-viem/network-helpers";
import { deployResolverWithAttestations } from "./utils";

async function deployFixture() {
  const result = await deployResolverWithAttestations();

  // You can copy code from other unit test files in case you want more functionalities

  return result
}

describe("POC", function () {
  it("Test case", async function () {
    const {
      publicKeyVerifier,
      resolver,
      walletOnchainVerifier,
      walletOptimisticVerifier,
      membership,
      simpleConsumer,
      schemaRegistry,
      eas,
      alices,
      fids,
    } = await loadFixture(deployFixture);

    // Your test cases here
  });
})
