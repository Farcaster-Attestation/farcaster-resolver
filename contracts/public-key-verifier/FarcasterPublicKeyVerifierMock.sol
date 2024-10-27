// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IFarcasterPublicKeyVerifier.sol";
import "./IKeyRegistry.sol";

contract FarcasterPublicKeyVerifierMock is IFarcasterPublicKeyVerifier {
    /// @notice The Key Registry mapping.
    mapping(uint256 => mapping(bytes32 => bool)) public keyRegistry;

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
        return keyRegistry[fid][publicKey];
    }

    function addKey(uint256 fid, bytes32 publicKey) external {
        keyRegistry[fid][publicKey] = true;
    }
}
