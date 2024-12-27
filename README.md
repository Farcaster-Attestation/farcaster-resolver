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

## Attesting Wallet Verification

The first step in verifying a wallet on Farcaster is to bring its verification on-chain. Anyone can attest a wallet’s verification because it relies on a signed verification message broadcast over the Farcaster Hub.

> **Note**  
> Attestation is usually performed automatically by a relayer, though there may be a fallback to a user-driven process if the relayer fails.

You will need to retrieve your verification message from the Farcaster Hub. Then, call the FarcasterResolver contract to either:
- **attest** a new wallet verification, or
- **revoke** an existing onchain verification.

```solidity
function attest(
    address recipient,
    uint256 fid,
    bytes32 publicKey,
    uint256 verificationMethod,
    bytes memory signature
) public returns (bytes32)

function revoke(
    address recipient,
    uint256 fid,
    bytes32 publicKey,
    uint256 verificationMethod,
    bytes memory signature
) public returns (bool)
```

Parameters for `attest` and `revoke`:
1. **recipient** – The wallet address that is being verified
2. **fid** – The Farcaster FID (Farcaster ID) of the verifying user
3. **publicKey** – The Farcaster public key used to sign the wallet verification message (details below)
4. **verificationMethod** - 1 (Onchain) or 2 (Optimistic) (details below)
5. **signature** – The encoded verification message and signature (details below)

### Verification Methods

There are two verification methods: Onchain (1) and Optimistic (2)

1. **Onchain Verification**  
   - **Permissionless:** Anyone can submit an on-chain verification. The signature and message are being verified fully on-chain in the smart contract.
   - **Pros:** Verification is instantaneous once the transaction is confirmed.  
   - **Cons:** Higher gas costs.

2. **Optimistic Verification**  
   - **Trust-but-Verify:** A whitelisted relayer submits the verification, which can be challenged by anyone within one day if it’s malicious.  
   - **Pros:** Lower gas costs compared to on-chain verification.  
   - **Cons:** Relies on a whitelisted relayer and includes a one-day challenge period; not open to public submissions.

### Getting publicKey and signature (verification message)

TODO

## Querying Wallet Verification Data

In addition to attestation, the `FarcasterResolver` contract lets you query wallet verification data directly.

### Checking if a Wallet Address and FID Are Verified

To check if a specific wallet address and Farcaster FID pair is verified, call the `isVerified` function:

```solidity
function isVerified(
    uint256 fid,
    address wallet
) public view returns (bool)
```

### Retrieving the Attestation UID

To retrieve the attestation UID for a verified wallet-FID pair, call the `getAttestationUid` function:

```solidity
function getAttestationUid(
    uint256 fid,
    address wallet
) public view returns (bytes32)
```
