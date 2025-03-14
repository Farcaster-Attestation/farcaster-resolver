// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IFarcasterWalletVerifier
 * @dev Interface for verifying Farcaster wallet verifications on-chain.
 */
interface IFarcasterWalletVerifier {
    /**
     * @notice Verifies a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified, encoded as (r, s, message).
     * @return uint256 indicating timestamp of the verification or 0 if the verification is not valid.
     */
    function verifyAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) external view returns (uint256);

    /**
     * @notice Verifies the removal of a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be removed.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified, encoded as (r, s, message).
     * @return uint256 indicating timestamp of the verification or 0 if the verification is not valid.
     */
    function verifyRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) external view returns (uint256);
}
