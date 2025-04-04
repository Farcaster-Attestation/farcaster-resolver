rm -rf ignition/deployments/supersim-10
rm -rf ignition/deployments/supersim-8453

npx hardhat ignition deploy ignition/modules/FarcasterResolver.ts --network supersim_op --deployment-id supersim-10
npx hardhat ignition deploy ignition/modules/FarcasterResolverExtended.ts --network supersim_op --deployment-id supersim-10 --parameters ./ignition/parameters/supersim.json --strategy create2
npx hardhat ignition deploy ignition/modules/FarcasterResolverExtended.ts --network supersim_base --deployment-id supersim-8453 --parameters ./ignition/parameters/supersim.json --strategy create2