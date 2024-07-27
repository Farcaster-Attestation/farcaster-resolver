// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./IFarcasterWalletVerifier.sol";
import {MessageType} from "@farcaster-attestation/farcaster-solidity/contracts/protobufs/message.proto.sol";

/**
 * @title FarcasterWalletOptimisticVerifier
 * @dev Contract for verifying Farcaster wallet verifications in an optimistic way with a 1 day challenging period for gas saving.
 */
contract FarcasterWalletOptimisticVerifier is
    IFarcasterWalletVerifier,
    Ownable
{
    error InvalidMessageType(MessageType messageType);
    error ChallengeFailed();

    /// @notice The on-chain verifier contract.
    IFarcasterWalletVerifier public immutable onchainVerifier;

    /// @notice The challenging period duration.
    uint256 public challengingPeriod = 1 days;

    /**
     * @dev Constructor to set the on-chain verifier and the relayer address.
     * @param verifier The address of the on-chain verifier contract to use in the challenging process.
     * @param relayer The address of the relayer.
     */
    constructor(
        IFarcasterWalletVerifier verifier,
        address relayer
    ) Ownable(relayer) {
        onchainVerifier = verifier;
    }

    /// @notice Mapping of verification hash to the timestamp of verification.
    mapping(bytes32 => uint256) public verificationTimestamp;

    /**
     * @notice Calculate the verification hash.
     * @param messageType The type of the message.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified.
     * @return bytes32 The hash of the verification details.
     */
    function hash(
        MessageType messageType,
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public pure returns (bytes32) {
        if (
            messageType !=
            MessageType.MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS &&
            messageType != MessageType.MESSAGE_TYPE_VERIFICATION_REMOVE
        ) {
            revert InvalidMessageType(messageType);
        }

        return
            keccak256(
                abi.encode(
                    messageType,
                    fid,
                    verifyAddress,
                    publicKey,
                    signature
                )
            );
    }

    /**
     * @dev Event emitted when a verification is submitted.
     * @param messageType The type of the message.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param hash The hash of the verification details.
     * @param signature The signature to be verified.
     */
    event SubmitVerification(
        MessageType indexed messageType,
        uint256 indexed fid,
        address indexed verifyAddress,
        bytes32 publicKey,
        bytes32 hash,
        bytes signature
    );

    /**
     * @notice Submits a verification for optimistic verification. Relayer only!
     * @param messageType The type of the message.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified.
     */
    function submitVerification(
        MessageType messageType,
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public onlyOwner {
        bytes32 h = hash(messageType, fid, verifyAddress, publicKey, signature);

        verificationTimestamp[h] = block.timestamp;

        emit SubmitVerification(
            messageType,
            fid,
            verifyAddress,
            publicKey,
            h,
            signature
        );
    }

    /**
     * @notice Verify if the verification has been submitted and if the challenging period has passed.
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
        bytes32 h = hash(
            MessageType.MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS,
            fid,
            verifyAddress,
            publicKey,
            signature
        );

        return
            verificationTimestamp[h] > 0 &&
            block.timestamp >= verificationTimestamp[h] + challengingPeriod;
    }

    /**
     * @notice Verify if the removal has been submitted and if the challenging period has passed.
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
    ) external view returns (bool) {
        bytes32 h = hash(
            MessageType.MESSAGE_TYPE_VERIFICATION_REMOVE,
            fid,
            verifyAddress,
            publicKey,
            signature
        );

        return
            verificationTimestamp[h] > 0 &&
            block.timestamp >= verificationTimestamp[h] + challengingPeriod;
    }

    /**
     * @dev Event emitted when a verification is challenged.
     * @param messageType The type of the message.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param hash The hash of the verification details.
     * @param signature The signature to be verified.
     */
    event Challenged(
        MessageType indexed messageType,
        uint256 indexed fid,
        address indexed verifyAddress,
        bytes32 publicKey,
        bytes32 hash,
        bytes signature
    );

    /**
     * @notice Challenges the Farcaster wallet verification submission.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified.
     */
    function challengeAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public {
        bytes32 h = hash(
            MessageType.MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS,
            fid,
            verifyAddress,
            publicKey,
            signature
        );

        if (verificationTimestamp[h] > 0) {
            try
                onchainVerifier.verifyAdd(
                    fid,
                    verifyAddress,
                    publicKey,
                    signature
                )
            returns (bool verified) {
                if (verified) {
                    revert ChallengeFailed();
                }
            } catch {}

            verificationTimestamp[h] = 0;

            emit Challenged(
                MessageType.MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS,
                fid,
                verifyAddress,
                publicKey,
                h,
                signature
            );
        }
    }

    /**
     * @notice Challenges the removal of a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified.
     */
    function challengeRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public {
        bytes32 h = hash(
            MessageType.MESSAGE_TYPE_VERIFICATION_REMOVE,
            fid,
            verifyAddress,
            publicKey,
            signature
        );

        if (verificationTimestamp[h] > 0) {
            try
                onchainVerifier.verifyRemove(
                    fid,
                    verifyAddress,
                    publicKey,
                    signature
                )
            returns (bool verified) {
                if (verified) {
                    revert ChallengeFailed();
                }
            } catch {}

            verificationTimestamp[h] = 0;

            emit Challenged(
                MessageType.MESSAGE_TYPE_VERIFICATION_REMOVE,
                fid,
                verifyAddress,
                publicKey,
                h,
                signature
            );
        }
    }
}
