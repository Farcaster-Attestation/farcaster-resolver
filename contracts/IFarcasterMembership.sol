// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {IFarcasterVerification} from "./IFarcasterVerification.sol";

// Permission flags for membership roles
// Combine flags with bitwise OR (|) to grant multiple permissions
uint256 constant FARCASTER_MEMBERSHIP_CAN_ATTEST = 1 << 0; // Can create attestations
uint256 constant FARCASTER_MEMBERSHIP_CAN_REVOKE = 1 << 1; // Can revoke attestations
uint256 constant FARCASTER_MEMBERSHIP_CAN_LEAVE = 1 << 2; // Can remove oneself from the group
uint256 constant FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER = 1 << 3; // Can add new members
uint256 constant FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER = 1 << 4; // Can remove other members
uint256 constant FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN = 1 << 5; // Can add new superadmins/admins/members
uint256 constant FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN = 1 << 6; // Can remove superadmins/admins/members

/**
 * @title IFarcasterMembership
 * @notice Interface for managing membership and permission structures for on-chain Farcaster attestations
 * @dev Enables features such as adding/removing members and setting members' permissions to reference an attestation
 */
interface IFarcasterMembership {
    /**
     * @notice Emitted when a member's permissions are set or updated
     * @param attUid The attestation UID for this membership group
     * @param adminFid The Farcaster ID of the admin performing this action
     * @param memberFid The Farcaster ID of the member whose permissions were set
     * @param permissions The new permission bitmask granted to memberFid
     */
    event SetMember(
        bytes32 indexed attUid,
        uint256 indexed adminFid,
        uint256 indexed memberFid,
        uint256 permissions
    );

    /**
     * @notice Emitted when a member is removed from the group
     * @param attUid The attestation UID for this membership group
     * @param adminFid The Farcaster ID of the admin performing the removal
     * @param memberFid The Farcaster ID of the removed member
     */
    event RemoveMember(
        bytes32 indexed attUid,
        uint256 indexed adminFid,
        uint256 indexed memberFid
    );

    /**
     * @notice Struct representing a member's status and permissions
     * @param farcasterId The member's Farcaster ID
     * @param permissions The member's permission bitmask
     */
    struct Membership {
        uint256 farcasterId;
        uint256 permissions;
    }

    /**
     * @notice Gets the Farcaster verification contract
     * @return The IFarcasterVerification contract interface
     */
    function verifier() external view returns (IFarcasterVerification);

    /**
     * @notice Gets the schema ID for membership attestations
     * @return The schema ID bytes32 value
     */
    function schemaId() external view returns (bytes32);

    /**
     * @notice Gets a member's status and permissions for a given attestation
     * @param attUid The attestation UID
     * @param farcasterId The Farcaster ID to check
     * @return joined Whether the Farcaster ID is a member
     * @return permissions The member's permission bitmask
     */
    function getMember(
        bytes32 attUid,
        uint256 farcasterId
    ) external view returns (bool joined, uint256 permissions);

    /**
     * @notice Gets the total number of members for an attestation
     * @param attUid The attestation UID
     * @return The number of members
     */
    function countMembers(bytes32 attUid) external view returns (uint256);

    /**
     * @notice Verifies if a member has specific permissions
     * @param attUid The attestation UID
     * @param fid The Farcaster ID to verify
     * @param permissions The permissions to check for
     * @return Whether the member has the specified permissions
     */
    function verifyMember(
        bytes32 attUid,
        uint256 fid,
        uint256 permissions
    ) external returns (bool);

    /**
     * @notice Gets all members and their permissions for an attestation
     * @param attUid The attestation UID
     * @return _members Array of Membership structs containing member data
     */
    function getMembers(
        bytes32 attUid
    ) external view returns (Membership[] memory _members);

    /**
     * @notice Adds or updates a member's permissions
     * @param attUid The attestation UID
     * @param adminFid The Farcaster ID of the admin performing this action
     * @param memberFid The Farcaster ID of the member to update
     * @param permissions The permission bitmask to grant
     */
    function setMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid,
        uint256 permissions
    ) external;

    /**
     * @notice Removes a member from the group
     * @param attUid The attestation UID
     * @param adminFid The Farcaster ID of the admin (or member themselves) performing this removal
     * @param memberFid The Farcaster ID of the member to remove
     */
    function removeMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid
    ) external;
}
