# Farcaster Resolver

Issuing attestations through a verified Farcaster wallet on the Superchain

## Deployments

* FarcasterResolverModule#Blake3 - [0xe9875D3A0D0dC78222aE01b2252d03F03CC3D018](https://optimistic.etherscan.io/address/0xe9875D3A0D0dC78222aE01b2252d03F03CC3D018)
* FarcasterResolverModule#Ed25519_pow - [0x2782355596D62F991544E58F02cDb4237018eBC7](https://optimistic.etherscan.io/address/0x2782355596D62F991544E58F02cDb4237018eBC7)
* FarcasterResolverModule#FarcasterPublicKeyVerifier - [0x20725BEf386c289110a54C8586D146EBb5Ed8C0b](https://optimistic.etherscan.io/address/0x20725BEf386c289110a54C8586D146EBb5Ed8C0b)
* FarcasterResolverModule#FcVerificationDecoder - [0x3e189132eE05415fB1068d3086D4c1C3Cb37de37](https://optimistic.etherscan.io/address/0x3e189132eE05415fB1068d3086D4c1C3Cb37de37)
* FarcasterResolverModule#Sha512 - [0x57bb00a1E7f9D03bcc042fAF82CCA248ec6F0f3f](https://optimistic.etherscan.io/address/0x57bb00a1E7f9D03bcc042fAF82CCA248ec6F0f3f)
* FarcasterResolverModule#Ed25519 - [0x53A1E44420Fd09D089dd38f0dffEeEfB62Fd6826](https://optimistic.etherscan.io/address/0x53A1E44420Fd09D089dd38f0dffEeEfB62Fd6826)
* FarcasterResolverModule#FarcasterResolver - [0xF99C4e843033831c570946a97F6195e47051C443](https://optimistic.etherscan.io/address/0xF99C4e843033831c570946a97F6195e47051C443)
* FarcasterResolverModule#FcMessageVerification - [0x80b87f98840fE76bEb44b97bc5FE00457eaAEdb0](https://optimistic.etherscan.io/address/0x80b87f98840fE76bEb44b97bc5FE00457eaAEdb0)
* FarcasterResolverModule#FarcasterWalletOnchainVerifier - [0xDcC7372912D743C52fD83bc7aB7810c40f449D3f](https://optimistic.etherscan.io/address/0xDcC7372912D743C52fD83bc7aB7810c40f449D3f)
* FarcasterResolverModule#FarcasterWalletOptimisticVerifier - [0x0F12f716DFf14195875a2Da46d843770D32256d9](https://optimistic.etherscan.io/address/0x0F12f716DFf14195875a2Da46d843770D32256d9)
* FarcasterResolverExtendedModule#FarcasterResolverInterop - [0x98561CaF79eb6a22B23fEb6366f798d7F3898c44](https://optimistic.etherscan.io/address/0x98561CaF79eb6a22B23fEb6366f798d7F3898c44)
* FarcasterResolverExtendedModule#FarcasterMembership - [0x4FFf1356BFBC3F736c0f84412bf79358a618de3d](https://optimistic.etherscan.io/address/0x4FFf1356BFBC3F736c0f84412bf79358a618de3d)
* FarcasterResolverExtendedModule#FarcasterResolverSimpleConsumer - [0x1a7eaD65F850862dAf2C9E3d65a43E7A4ff20C28](https://optimistic.etherscan.io/address/0x1a7eaD65F850862dAf2C9E3d65a43E7A4ff20C28)

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

*Note: FcVerificationDecoder, FcMessageVerification and their dependencies are on a separated repository: https://github.com/Farcaster-Attestation/farcaster-decoder*

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

### Deploying contracts on supersim

Supersim is a lightweight tool designed to simulate the Superchain. It is primarily used to test the `FarcasterResolverInterop`. The following command launches forked OP and Base chains simultaneously and sets up an L2 <-> L2 cross-chain interoperability simulation:

```
supersim fork --chains op,base --interop.autorelay
```

After starting Supersim, run the following command to deploy the necessary contracts:

```
./deploy-supersim.sh
```

Note that the `FarcasterResolverExtended` is deployed using a deterministic deployment strategy, ensuring it is deployed to the same address across all chains.

The first wallet in the test mnemonic (test junk) is designated as both the deployer and the admin of the contracts.

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

You can get verification messages of any FID by querying from the Farcaster Hub: https://docs.farcaster.xyz/reference/hubble/httpapi/verification

```
curl https://nemes.farcaster.xyz:2281/v1/verificationsByFid?fid=328679
```

Response:

```json
{
  "messages":[
    {
      "data":{
        "type":"MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS",
        "fid":328679,
        "timestamp":100412508,
        "network":"FARCASTER_NETWORK_MAINNET",
        "verificationAddAddressBody":{
          "address":"0xf01dd015bc442d872275a79b9cae84a6ff9b2a27",
          "claimSignature":"IsbQTvpf5U1v31NcLHuJS6UeThEQLx1cyVVr5lZ0w7UN2TDKzVdyx6qpKdjwnTmjJ/xfG6s0oNbcNB2PlG+FFhw=",
          "blockHash":"0x39dfd535c2173c551c4ed55dbb2d52a07951cd68852547509ce066720d251473",
          "verificationType":0,
          "chainId":0,
          "protocol":"PROTOCOL_ETHEREUM",
          "ethSignature":"IsbQTvpf5U1v31NcLHuJS6UeThEQLx1cyVVr5lZ0w7UN2TDKzVdyx6qpKdjwnTmjJ/xfG6s0oNbcNB2PlG+FFhw="
        },
        "verificationAddEthAddressBody":{
          "address":"0xf01dd015bc442d872275a79b9cae84a6ff9b2a27",
          "claimSignature":"IsbQTvpf5U1v31NcLHuJS6UeThEQLx1cyVVr5lZ0w7UN2TDKzVdyx6qpKdjwnTmjJ/xfG6s0oNbcNB2PlG+FFhw=",
          "blockHash":"0x39dfd535c2173c551c4ed55dbb2d52a07951cd68852547509ce066720d251473",
          "verificationType":0,
          "chainId":0,
          "protocol":"PROTOCOL_ETHEREUM",
          "ethSignature":"IsbQTvpf5U1v31NcLHuJS6UeThEQLx1cyVVr5lZ0w7UN2TDKzVdyx6qpKdjwnTmjJ/xfG6s0oNbcNB2PlG+FFhw="
        }
      },
      "hash":"0x4576a545b9ddda33e3629e84ae86f8b904c106d5",
      "hashScheme":"HASH_SCHEME_BLAKE3",
      "signature":"j2EmRG5mjZNzXgFfdNphfR+6/9FHHDzV9ZFGLTVuOJBrgK/fWt7L6dyMdCOyqig6M3LbHCXDPTL+McDFQcOGDA==",
      "signatureScheme":"SIGNATURE_SCHEME_ED25519",
      "signer":"0xbb77ee11e6651a87e4537d80eca20ee9036b0260eb77150065b2c02148f9603a"
    },
    ...
  ]
}
```

However, we can only get verification add message by this method, not verification remove

With this response, let `message = messages[i]`, we have
* `publicKey` = `message.signer`
* `signature` = `abi.encode(r,s,messageData)` of types `(bytes32, bytes32, bytes)`
    - `r` = `message.signature.subarray(0, 32)`
    - `s` = `message.signature.subarray(32)`
    - `messageData` = `MessageData.encode(message.data).finish()`
 
Please look at [FarcasterWalletVerifier.ts unit test](./test/FarcasterWalletVerifier.ts) for additional implementation examples.

### How to verify your wallet address with your FID

Go to https://warpcast.com/~/settings/verified-addresses and verify your address

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

### Retrieving All Wallets for a Farcaster ID

```solidity
function getFidAttestations(
    uint256 fid
) public view returns (address[] memory wallets, bytes32[] memory uids)
```

#### How it Works
- **Input**: A Farcaster ID (`fid`).
- **Output**:
  - An array of wallet addresses (`wallets`) that have been verified for the specified `fid`.  
  - An array of attestation UIDs (`uids`) representing on-chain attestations.

#### Example Usage

```solidity
(address[] memory wallets, bytes32[] memory uids) = farcasterResolver.getFidAttestations(fid);
```

This call returns all verified wallet addresses for the given Farcaster ID. Each attestation is uniquely identified by the corresponding `uids` array.

### Retrieving All FIDs for a Wallet

```solidity
function getWalletAttestations(
    address wallet
) public view returns (uint256[] memory fids, bytes32[] memory uids)
```

#### How it Works
- **Input**: A wallet address (`wallet`).
- **Output**:
  - An array of Farcaster IDs (`fids`) that have been attested for the specified wallet.  
  - An array of attestation UIDs (`uids`) representing on-chain attestations.

#### Example Usage

```solidity
(uint256[] memory fids, bytes32[] memory uids) = farcasterResolver.getWalletAttestations(wallet);
```

This call returns all Farcaster IDs that the specified wallet address has verified, along with their unique attestation identifiers.

## Developing an EAS Resolver for Farcaster Attestation Schemas

To enable fully on-chain Farcaster attestations for your schema, you must deploy your schema with a resolver that verifies the wallet attestation. To simplify development, we provide two types of resolver consumer contracts: **FarcasterResolverSimpleConsumer** and **FarcasterResolverStandardConsumer**.

We also offer an abstract contract, `FarcasterResolverConsumer`, which you can inherit to create a custom resolver. By implementing the `decodeFarcasterAttestation` function in your custom contract, you can decode the wallet address and FID from the attestation body for verification.

### FarcasterResolverSimpleConsumer
**FarcasterResolverSimpleConsumer** is a predeployed resolver contract that can be used immediately for Farcaster-verified wallet attestations. Here’s what you need to know:
- **No Additional Deployment:** You can directly use this predeployed contract as your resolver.
- **Schema Requirements:** The schema must include a `bytes32 fid` as its first field.
- The attester’s wallet is used with the FID to verify the attestation.
- If you need a more customized solution, you must deploy your own resolver by using the `FarcasterResolverStandardConsumer` described below.

### FarcasterResolverStandardConsumer
**FarcasterResolverStandardConsumer** is an advanced resolver consumer contract built on top of **FarcasterResolverConsumer**, offering greater customization for verifying Farcaster attestations. It supports:

- Verifying Farcaster attestations with flexible configurations.  
- Referencing and validating a secondary attestation.  
- Schemas designed for organizational or membership structures.

Unlike the simple consumer, the standard consumer requires you to deploy your own resolver consumer contract, supplying the necessary configurations.

```solidity
constructor(
    IEAS _eas,
    IFarcasterVerification _resolver,
    IFarcasterMembership _membership,
    bool _useRecipient,
    bool _useRefFid,
    bool _useRefCheck,
    bool _useRefBody,
    uint256 _fidOffset,
    uint256 _refOffset
) FarcasterResolverConsumer(_eas, _resolver)
```

#### Constructor Arguments
- **_eas**: [Ethereum Attestation Service (EAS)](https://github.com/ethereum-attestation-service) contract address.  
- **_resolver**: `FarcasterResolverInterop` contract address.
- **_membership**: `FarcasterMembership` contract address.
- **_useRecipient**: If `true`, uses the attestation’s recipient for wallet verification; otherwise, uses the attester.  
- **_useRefFid**: If `true`, retrieves the FID from a referenced attestation’s data rather than from the primary attestation’s data.  
- **_useRefCheck**: If `true`, performs membership and permission checks on the referenced attestation.  
- **_useRefBody**: If `true`, reads `refUID` from the attestation body; otherwise, reads `Attestation.refUID`.  
- **_fidOffset**: The byte offset in `Attestation.data` where the FID is located (when `_useRefFid` is `false`).  
- **_refOffset**: The byte offset in `Attestation.data` where the `refUID` is located (when `_useRefBody` is `true`).

### Common Scenarios

Below are some common configurations for **FarcasterResolverStandardConsumer**.

#### 1. Verifying the Attester Against the FID in the First Field
- **Schema:** `(bytes32 fid, ...)`
- **Settings:**
  - `_useRecipient = false`
  - `_useRefFid = false`
  - `_useRefCheck = false`
  - `_useRefBody = false`
  - `_fidOffset = 0`
  - `_refOffset = 0`

#### 2. Verifying the Recipient Against the FID in the Second Field
- **Schema:** `(bytes32 a, bytes32 fid, ...)`
- **Settings:**
  - `_useRecipient = true`
  - `_useRefFid = false`
  - `_useRefCheck = false`
  - `_useRefBody = false`
  - `_fidOffset = 32`
  - `_refOffset = 0`

#### 3. Verifying the Attester Against the FID from a Referenced Attestation
- **Referenced Attestation:** Must implement a Farcaster resolver consumer
- **Settings:**
  - `_useRecipient = false`
  - `_useRefFid = true`
  - `_useRefCheck = false`
  - `_useRefBody = false`
  - `_fidOffset = 0`
  - `_refOffset = 0`

#### 4. Verifying the Attester Against the FID from a Referenced Attestation in Attestation Data
- **Schema:** `(bytes32 refUID, ...)`
- **Settings:**
  - `_useRecipient = false`
  - `_useRefFid = true`
  - `_useRefCheck = false`
  - `_useRefBody = true`
  - `_fidOffset = 0`
  - `_refOffset = 0`

#### 5. Verifying the Attester Against the FID from a Referenced Attestation in the Second Field
- **Schema:** `(bytes32 a, bytes32 refUID, ...)`
- **Settings:**
  - `_useRecipient = false`
  - `_useRefFid = true`
  - `_useRefCheck = false`
  - `_useRefBody = true`
  - `_fidOffset = 0`
  - `_refOffset = 32`

#### 6. Verifying the Attester’s FID and Checking Membership Permissions
- **Schema:** `(bytes32 fid, ...)`
- **Referenced Attestation:** Must implement a Farcaster resolver consumer
- **Settings:**
  - `_useRecipient = false`
  - `_useRefFid = false`
  - `_useRefCheck = true`
  - `_useRefBody = false`
  - `_fidOffset = 0`
  - `_refOffset = 0`
 
## Membership System

**FarcasterMembership** is a contract that manages membership and permission structures for on-chain Farcaster attestations. It enables features such as adding/removing members, and settings members’ permissions to reference an attestation.

By using **FarcasterMembership**, organizations can manage membership permissions and roles on-chain without needing a separate identity system. The contract leverages EAS attestations and Farcaster’s verification flow to streamline membership operations.

### Permissions

Permissions are represented as bit flags. Combine them with bitwise OR (`|`) to grant multiple permissions:

| Permission                          | Flag Value | Description                          |
|------------------------------------|-----------|--------------------------------------|
| `FARCASTER_MEMBERSHIP_CAN_ATTEST`  | `1 << 0`  | Can create attestations              |
| `FARCASTER_MEMBERSHIP_CAN_REVOKE`  | `1 << 1`  | Can revoke attestations              |
| `FARCASTER_MEMBERSHIP_CAN_LEAVE`   | `1 << 2`  | Can remove oneself from the group    |
| `FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER`   | `1 << 3`  | Can add new members                  |
| `FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER`| `1 << 4`  | Can remove other members             |
| `FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN`    | `1 << 5`  | Can add new superadmins / admins / members         |
| `FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN` | `1 << 6`  | Can remove new superadmins / admins / members      |

### Member vs. Admin vs. Superadmin

#### Member
- A **Member** lacks any add/remove or admin-related permissions. Specifically, they do **not** have `FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER`, `FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER`, `FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN`, or `FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN`.
- Members can only perform the actions (e.g., attest, revoke) granted to them by an admin.

#### Admin
- An **Admin** can add or remove **members** but cannot promote or remove other admins or superadmins. They possess `FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER` and `FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER` but **do not** have `FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN` or `FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN`.
- Admins inherit all member permissions, including attesting, revoking, and leaving. They can also promote themselves to any membership-level permission (attest/revoke/leave).

#### Superadmin
- A **Superadmin** can add or remove **anyone**, including other admins and superadmins. They have `FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN` and `FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN`.
- Superadmins inherit all admin permissions and can manage every membership level. They can remove other superadmins, so this role should be assigned with caution.
- Although a superadmin can revoke the original attester’s permissions, the original attester automatically regains them if all superadmins, admins, and members are removed.

### Workflow Summary

1. **InitMembership:**  
   - The first time `setMember` or `removeMember` is called on a new attestation `attUid`, the contract inspects the underlying attestation to locate the primary FID.  
   - That primary FID is granted all permissions by default.  

2. **Adding a Member:**  
   ```solidity
   function setMember(
       bytes32 attUid,
       uint256 adminFid,
       uint256 memberFid,
       uint256 permissions
   ) external;
   ```
   - **Parameters:**
       - `attUid`: The attestation UID for this membership group.
       - `adminFid`: The Farcaster ID of the admin performing this action.
       - `memberFid`: The Farcaster ID of the new or existing member whose permissions are being set.
       - `permissions`: A bitmask of permissions to grant to memberFid.
   - **Workflow:**
       1. The contract checks if `adminFid` is verified by calling `verifier.isVerified(adminFid, msg.sender)`.
       2. If `adminFid` has the appropriate permissions (`CAN_ADD_MEMBER` or `CAN_ADD_ADMIN`), the contract updates the membership details in storage.
       3. Internally, an EAS attestation referencing `attUid` is also created or updated, recording these membership permissions on-chain.

3. **Removing a Member:**  
   ```solidity
   function removeMember(
       bytes32 attUid,
       uint256 adminFid,
       uint256 memberFid
   ) external;
   ```
   - **Parameters**:
     - **`attUid`**: The attestation UID for this membership group. 
     - **`adminFid`**: The Farcaster ID of the admin (or member themselves) performing this removal.  
     - **`memberFid`**: The Farcaster ID of the member to be removed.
     - If a member is leaving on his own, enter the same `adminFid` = `memberFid`
   - **Workflow**:
     1. The contract verifies that `adminFid` is linked to `msg.sender`.  
     2. Checks if `adminFid` has the necessary permissions (`CAN_REMOVE_MEMBER` or `CAN_REMOVE_ADMIN`). If removing oneself, checks for `CAN_LEAVE`.  
     3. Revokes the internal EAS attestation linked to `memberFid`. This effectively removes `memberFid` from the membership.

5. **Permission Checks:**  
   ```solidity
   function verifyMember(bytes32 attUid, uint256 fid, uint256 permissions) external returns(bool);
   ```
   - Call `verifyMember` to confirm that a given `fid` has the specified `permissions` in the membership.  
   - Can be used to gate other on-chain logic.

### Example Use Case

1. **Organization Onboarding:**  
   - A DAO or group on Farcaster sets up a membership attestation (`attUid`).  
   - The contract reads the primary FID from the attestation and grants it administrative permissions.  

2. **Admin Adds Team Members:**  
   - The admin calls `setMember(attUid, adminFid, newMemberFid, desiredPermissions)`.  
   - As long as the admin has the `CAN_ADD_MEMBER` or `CAN_ADD_ADMIN` permission, and desired permission isn't exceeded his permission level, the function succeeds.  

3. **Member Performs Actions:**  
   - The new member can create or revoke attestations, subject to their permissions.  
   - Third-party contracts can call `verifyMember(attUid, memberFid, requiredPermission)` before accepting an action (e.g., revoking another member).

4. **Removing Members:**  
   - If a member leaves, `removeMember(attUid, adminFid, memberFid)` is called.  
   - If the member has `CAN_LEAVE` and they’re removing themselves, they can call the same function with their own FID.  
