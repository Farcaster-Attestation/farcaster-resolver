# Farcaster Resolver

Issuing attestations through a verified Farcaster wallet on the Superchain

## Architecture

![image](https://github.com/user-attachments/assets/ef0e9c34-c459-41dc-bd36-87ad747e0bb6)

- **FarcasterResolver** - The primary contract that verifies and stores the relationship between a Farcaster-verified wallet address and its FID.
- **FarcasterResolverInterop** - A wrapper for FarcasterResolver, enabling interoperability across the Superchain with deterministic deployment to the same address.
- **FarcasterPublicKeyVerifier** - A contract that validates public keys and FIDs against the Farcaster KeyRegistry.
- **FarcasterOnchainVerifier** - A contract that fully computes and verifies Farcaster wallet verification add/remove messages directly on-chain.
- **FarcasterOptimisticVerifier** - A contract that verifies Farcaster wallet verification add/remove messages optimistically by relying on trusted, whitelisted relays. It includes a one-day challenge period, allowing anyone to dispute and verify the messages on-chain.
- **FcVerificationDecoder** - Library for decoding Farcaster verification GRPC-encoded messages.  
- **FcMessageVerification** - Library for verifying Farcaster message signatures.  
- **FarcasterResolverConsumer** - Abstract contract template for implementing resolvers requiring Farcaster verification.  
- **FarcasterResolverSimpleConsumer** - Simple resolver for schemas allowing only attestations from Farcaster-verified wallets.  
- **FarcasterResolverStandardConsumer** - Customizable resolver for schemas needing complex verification, such as reference and membership validation.  
- **FarcasterMembership** - Membership system enabling attestation owners to invite other Farcaster users to reference the attestation.  

## Building the project
 
The Farcaster Resolver is built using Hardhat. To run tests and deploy the contract, ensure you configure your private key and the Optimism RPC address in the `.env` file, as the tests are operated in fork mode.

### Setting the environment

Create an `.env` file with the following secrets

```
RPC_URL=<Optimism mainnet RPC>
RPC_TESTNET_URL=<Optimism sepolia testnet RPC>
PRIVATE_KEY=<Private key for contract deployment>
ETHERSCAN_API_KEY=<Etherscsn API Key>
```

### Compiling the contracts

```
npx hardhat compile
```

### Running tests

```
npx hardhat test
```

### Running coverage

```
npm run coverage
```
