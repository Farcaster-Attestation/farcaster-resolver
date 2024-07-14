// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IFarcasterPublicKeyVerifier.sol";
import "./IKeyRegistry.sol";

contract FarcasterPublicKeyVerifier is IFarcasterPublicKeyVerifier {
    IKeyRegistry public immutable keyRegistry;

    constructor(IKeyRegistry registry) {
        keyRegistry = registry;
    }

    function verifyPublicKey(
        uint256 fid,
        bytes32 publicKey
    ) external view returns (bool) {
        IKeyRegistry.KeyData memory data = IKeyRegistry(keyRegistry).keyDataOf(fid, abi.encodePacked(publicKey));
        return data.state == IKeyRegistry.KeyState.ADDED && data.keyType == 0;
    }
}
