// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {IFarcasterVerification} from "./IFarcasterVerification.sol";

interface IFarcasterMembership {
    event SetMember(
        bytes32 indexed attUid,
        uint256 indexed adminFid,
        uint256 indexed memberFid,
        uint256 permissions
    );
    event RemoveMember(
        bytes32 indexed attUid,
        uint256 indexed adminFid,
        uint256 indexed memberFid
    );

    struct Membership {
        uint256 farcasterId;
        uint256 permissions;
    }

    function verifier() external view returns (IFarcasterVerification);

    function schemaId() external view returns (bytes32);

    function getMember(
        bytes32 attUid,
        uint256 farcasterId
    ) external view returns (bool joined, uint256 permissions);

    function countMembers(bytes32 attUid) external view returns (uint256);

    function getMembers(
        bytes32 attUid
    ) external view returns (Membership[] memory _members);

    function setMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid,
        uint256 permissions
    ) external;

    function removeMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid
    ) external;
}
