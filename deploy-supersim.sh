rm -rf ignition/deployments/chain-10
rm -rf ignition/deployments/chain-8453

npx hardhat ignition deploy ignition/modules/FarcasterResolver.ts --network supersim_op
npx hardhat ignition deploy ignition/modules/FarcasterResolverExtended.ts --network supersim_op --parameters ./ignition/parameters/supersim.json --strategy create2
npx hardhat ignition deploy ignition/modules/FarcasterResolverExtended.ts --network supersim_base --parameters ./ignition/parameters/supersim.json --strategy create2