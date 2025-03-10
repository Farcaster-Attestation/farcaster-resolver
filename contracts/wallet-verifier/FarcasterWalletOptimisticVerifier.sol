// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {IFarcasterWalletVerifier} from "./IFarcasterWalletVerifier.sol";
import {IFarcasterPublicKeyVerifier} from "../public-key-verifier/IFarcasterPublicKeyVerifier.sol";
import {MessageType} from "@farcaster-attestation/farcaster-decoder/contracts/protobufs/message.proto.sol";

/**
 * @title FarcasterWalletOptimisticVerifier
 * @dev Contract for verifying Farcaster wallet verifications in an optimistic way with a 1 day challenging period for gas saving.
 */
contract FarcasterWalletOptimisticVerifier is
    IFarcasterWalletVerifier,
    AccessControl
{
    error InvalidMessageType(MessageType messageType);
    error InvalidPublicKey(uint256 fid, bytes32 publicKey);
    error ChallengeFailed();
    error NotEnoughDeposit(uint256 balance);
    error Disabled();
    error InsufficientGas();
    error SmartContractWalletNotAllowed();

    /// @notice Role identifier for relayer role
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /// @notice Role identifier for security role (Security Council)
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    /// @notice The on-chain verifier contract.
    IFarcasterWalletVerifier public immutable onchainVerifier;

    /// @notice Public key verifier contract
    IFarcasterPublicKeyVerifier public immutable publicKeyVerifier;

    /// @notice The challenging period duration.
    uint256 public immutable challengingPeriod;

    /// @notice The ETH amount that needed for security deposit.
    uint256 public immutable depositAmount;

    /// @notice Mapping of verification hash to the timestamp of verification.
    mapping(bytes32 => uint256) public verificationTimestamp;

    /// @notice A flag to indicate if the verifier is disabled.
    bool public disabled;

    modifier enoughDeposit() {
        if (disabled) {
            revert Disabled();
        }

        if (address(this).balance < depositAmount) {
            revert NotEnoughDeposit(address(this).balance);
        }

        _;
    }

    /**
     * @dev Constructor to set the on-chain verifier and the relayer address.
     * @param verifier The address of the on-chain verifier contract to use in the challenging process.
     * @param admin The address of the admin.
     */
    constructor(
        IFarcasterWalletVerifier verifier,
        IFarcasterPublicKeyVerifier pubKeyVerifier,
        uint256 _challengingPeriod,
        uint256 _depositAmount,
        address admin
    ) payable {
        onchainVerifier = verifier;
        publicKeyVerifier = pubKeyVerifier;

        challengingPeriod = _challengingPeriod;
        depositAmount = _depositAmount;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, admin);
    }

    receive() external payable {}

    /**
     * Disable a malicious relayer in an emergency by the security council.
     * @param relayer Relayer to be disabled
     */
    function disableRelayer(address relayer) public onlyRole(SECURITY_ROLE) {
        _revokeRole(RELAYER_ROLE, relayer);
    }

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
    ) public enoughDeposit onlyRole(RELAYER_ROLE) {
        if (verifyAddress.code.length > 0) {
            revert SmartContractWalletNotAllowed();
        }

        bool publicKeyVerified = publicKeyVerifier.verifyPublicKey(
            fid,
            publicKey
        );

        if (!publicKeyVerified) {
            revert InvalidPublicKey(fid, publicKey);
        }

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
    ) external view enoughDeposit returns (bool) {
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
    ) external view enoughDeposit returns (bool) {
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
     * @notice Calculate the reward amount for a successful challenge
     * @dev The reward is the entire contract balance because the optimistic verifier will be disabled after one valid challenge
     * @return uint256 The reward amount in wei to be paid to the challenger
     */
    function challengeReward() internal view returns (uint256) {
        return address(this).balance;
    }

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

            {
                (bool success, ) = payable(msg.sender).call{
                    value: challengeReward()
                }("");
                require(success);
            }

            disabled = true;

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

            {
                (bool success, ) = payable(msg.sender).call{
                    value: challengeReward()
                }("");
                require(success);
            }

            disabled = true;

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

    /**
     * @notice Try challenging the Farcaster wallet verification submission.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified.
     * @return true if the attestation must be challenged, false if valid
     */
    function tryChallengeAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public view returns (bool) {
        // Ensure minimum gas limit of ~4M for verification
        if (gasleft() < 3_900_000) {
            revert InsufficientGas();
        }
        
        try
            onchainVerifier.verifyAdd(fid, verifyAddress, publicKey, signature)
        returns (bool verified) {
            if (verified) {
                return false;
            }
        } catch {}

        return true;
    }

    /**
     * @notice Try challenging the removal of a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param signature The signature to be verified.
     * @return true if the attestation must be challenged, false if valid
     */
    function tryChallengeRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public view returns (bool) {
        // Ensure minimum gas limit of 4M for verification
        if (gasleft() < 3_900_000) {
            revert InsufficientGas();
        }

        try
            onchainVerifier.verifyRemove(
                fid,
                verifyAddress,
                publicKey,
                signature
            )
        returns (bool verified) {
            if (verified) {
                return false;
            }
        } catch {}

        return true;
    }
}
