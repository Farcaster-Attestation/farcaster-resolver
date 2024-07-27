// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IFarcasterWalletVerifier.sol";
import "@farcaster-attestation/farcaster-solidity/contracts/farcaster/FcMessageVerification.sol";
import "@farcaster-attestation/farcaster-solidity/contracts/farcaster/FcMessageDecoder.sol";

/**
 * @title FarcasterWalletOnchainVerifier
 * @dev Contract for verifying Farcaster wallet verifications on-chain.
 */
contract FarcasterWalletOnchainVerifier is IFarcasterWalletVerifier {
    /**
     * @notice Verifies a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified, encoded as (r, s, message).
     * @return bool indicating whether the verification was successful.
     */
    function verifyAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) external view returns (bool) {
        (bytes32 signature_r, bytes32 signature_s, bytes memory message) = abi
            .decode(signature, (bytes32, bytes32, bytes));

        if (
            !FcMessageVerification.verifyMessage(
                publicKey,
                signature_r,
                signature_s,
                message
            )
        ) return false;

        MessageDataVerificationAddAddress
            memory message_data = FcVerificationDecoder
                .decodeVerificationAddAddress(message);

        address target = bytesToAddress(
            message_data.verification_add_address_body.address_
        );

        if (target != verifyAddress || message_data.fid != fid) {
            return false;
        }

        return FcMessageVerification.verifyEthAddressClaim(message_data);
    }

    /**
     * @notice Verifies the removal of a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be removed.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified, encoded as (r, s, message).
     * @return bool indicating whether the verification was successful.
     */
    function verifyRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) external pure returns (bool) {
        (bytes32 signature_r, bytes32 signature_s, bytes memory message) = abi
            .decode(signature, (bytes32, bytes32, bytes));

        if (
            !FcMessageVerification.verifyMessage(
                publicKey,
                signature_r,
                signature_s,
                message
            )
        ) return false;

        MessageDataVerificationRemove
            memory message_data = FcVerificationDecoder
                .decodeVerificationRemove(message);

        address target = bytesToAddress(
            message_data.verification_remove_body.address_
        );

        if (target != verifyAddress || message_data.fid != fid) {
            return false;
        }

        return true;
    }
}
