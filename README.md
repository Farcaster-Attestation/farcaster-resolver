# Farcaster Resolver

Issuing attestations through a verified Farcaster wallet on the Superchain

## Architecture

![image](https://github.com/user-attachments/assets/ef0e9c34-c459-41dc-bd36-87ad747e0bb6)

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
