// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IFarcasterPublicKeyVerifier.sol";
import "./IKeyRegistry.sol";

contract FarcasterPublicKeyVerifier is IFarcasterPublicKeyVerifier {
    /// @notice The Key Registry contract.
    IKeyRegistry public immutable keyRegistry;

    /**
     * @dev Constructor to set the Key Registry contract.
     * @param registry The address of the Key Registry contract.
     */
    constructor(IKeyRegistry registry) {
        keyRegistry = registry;
    }

    /**
     * @notice Verifies if the given public key is valid for the specified Farcaster ID (FID).
     * @param fid The Farcaster ID (FID) of the user.
     * @param publicKey The public key to be verified.
     * @return bool indicating whether the public key is valid.
     */
    function verifyPublicKey(
        uint256 fid,
        bytes32 publicKey
    ) external view returns (bool) {
        IKeyRegistry.KeyData memory data = IKeyRegistry(keyRegistry).keyDataOf(fid, abi.encodePacked(publicKey));
        return data.state == IKeyRegistry.KeyState.ADDED && data.keyType == 1;
    }
}
