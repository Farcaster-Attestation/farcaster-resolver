// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./IFarcasterWalletVerifier.sol";
import {MessageType} from "@farcaster-attestation/farcaster-solidity/contracts/protobufs/message.proto.sol";

contract FarcasterWalletOptimisticVerifier is
    IFarcasterWalletVerifier,
    Ownable
{
    error InvalidMessageType(MessageType messageType);
    error ChallengeFailed();

    IFarcasterWalletVerifier public immutable onchainVerifier;
    uint256 public challengingPeriod = 1 days;

    constructor(
        IFarcasterWalletVerifier verifier,
        address relayer
    ) Ownable(relayer) {
        onchainVerifier = verifier;
    }

    mapping(bytes32 => uint256) public verificationTimestamp;

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

    event SubmitVerification(
        MessageType indexed messageType,
        uint256 indexed fid,
        address indexed verifyAddress,
        bytes32 publicKey,
        bytes32 hash,
        bytes signature
    );

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

    event Challenged(
        MessageType indexed messageType,
        uint256 indexed fid,
        address indexed verifyAddress,
        bytes32 publicKey,
        bytes32 hash,
        bytes signature
    );

    function challengeAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public {
        bool verified = onchainVerifier.verifyAdd(fid, verifyAddress, publicKey, signature);

        if (verified) {
            revert ChallengeFailed();
        }

        bytes32 h = hash(
            MessageType.MESSAGE_TYPE_VERIFICATION_ADD_ETH_ADDRESS,
            fid,
            verifyAddress,
            publicKey,
            signature
        );

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

    function challengeRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        bytes memory signature
    ) public {
        bool verified = onchainVerifier.verifyRemove(fid, verifyAddress, publicKey, signature);

        if (verified) {
            revert ChallengeFailed();
        }

        bytes32 h = hash(
            MessageType.MESSAGE_TYPE_VERIFICATION_REMOVE,
            fid,
            verifyAddress,
            publicKey,
            signature
        );

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
