// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import {SchemaResolver, ISchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaRecord} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IFarcasterResolverAttestationDecoder} from "./consumer/IFarcasterResolverAttestationDecoder.sol";
import "./IFarcasterMembership.sol";

/**
 * @title FarcasterMembership
 * @notice A contract that manages membership and permission structures for on-chain Farcaster attestations.
 * @dev Enables features such as adding/removing members and setting members' permissions to reference an attestation.
 * Leverages EAS attestations and Farcaster's verification flow to streamline membership operations.
 */
contract FarcasterMembership is
    IFarcasterMembership,
    SchemaResolver,
    Multicall
{
    using EnumerableMap for EnumerableMap.UintToUintMap;
    using ERC165Checker for address;
    error PermissionDenied();
    error MissingFarcasterResolverConsumer(bytes32 uid);
    error AttestationRevoked(bytes32 uid);
    error NoPrimaryFid(bytes32 uid);

    IFarcasterVerification public immutable verifier;
    bytes32 public schemaId;
    mapping(bytes32 => EnumerableMap.UintToUintMap) members;
    mapping(bytes32 => mapping(uint256 => bytes32)) public attestations;

    /**
     * @notice Constructs a new FarcasterMembership contract
     * @param eas The Ethereum Attestation Service contract
     * @param _verifier The Farcaster verification contract
     */
    constructor(
        IEAS eas,
        IFarcasterVerification _verifier
    ) SchemaResolver(eas) {
        verifier = _verifier;

        schemaId = eas.getSchemaRegistry().register(
            "uint256 adminFid,uint256 memberFid,uint256 permissions",
            ISchemaResolver(address(this)),
            true
        );
    }

    /**
     * @notice Decodes packed membership data into Farcaster ID and permissions
     * @param input The packed uint256 containing both values
     * @return farcasterId The Farcaster ID
     * @return permissions The permission bitmask
     */
    function decodePackedMembership(
        uint256 input
    ) internal pure returns (uint128 farcasterId, uint128 permissions) {
        farcasterId = uint128(input & type(uint128).max);
        permissions = uint128(input >> 128);
    }

    /**
     * @notice Checks if a permission bitmask contains a specific flag
     * @param permissions The permission bitmask to check
     * @param flag The permission flag to look for
     * @return bool True if the permission contains the flag
     */
    function hasPermission(
        uint256 permissions,
        uint256 flag
    ) internal pure virtual returns (bool) {
        return (permissions & flag) == flag;
    }

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
    ) public view returns (bool joined, uint256 permissions) {
        return members[attUid].tryGet(farcasterId);
    }

    /**
     * @notice Gets the total number of members for an attestation
     * @param attUid The attestation UID
     * @return uint256 The number of members
     */
    function countMembers(bytes32 attUid) public view returns (uint256) {
        return members[attUid].length();
    }

    /**
     * @notice Gets all members and their permissions for an attestation
     * @param attUid The attestation UID
     * @return _members Array of Membership structs containing Farcaster IDs and permissions
     */
    function getMembers(
        bytes32 attUid
    ) public view returns (Membership[] memory _members) {
        unchecked {
            uint256 count = countMembers(attUid);
            _members = new Membership[](count);

            EnumerableMap.UintToUintMap storage membersOnRef = members[attUid];

            for (uint256 i = 0; i < count; ++i) {
                (uint256 farcasterId, uint256 permissions) = membersOnRef.at(i);
                _members[i] = Membership({
                    farcasterId: farcasterId,
                    permissions: permissions
                });
            }
        }
    }

    /**
     * @notice Initializes membership for a new attestation
     * @dev Sets up the primary FID with admin permissions if no members exist
     * @param attUid The attestation UID
     */
    function initMember(bytes32 attUid) internal virtual {
        Attestation memory a = _eas.getAttestation(attUid);
        SchemaRecord memory schema = _eas.getSchemaRegistry().getSchema(
            a.schema
        );

        if (a.revocationTime > 0) revert AttestationRevoked(a.uid);

        if (members[attUid].length() == 0) {
            if (
                address(schema.resolver) == address(0) ||
                !address(schema.resolver).supportsInterface(
                    type(IFarcasterResolverAttestationDecoder).interfaceId
                )
            ) {
                revert MissingFarcasterResolverConsumer(attUid);
            }

            uint256 fid;
            uint256 permissions = 0;

            try
                IFarcasterResolverAttestationDecoder(address(schema.resolver))
                    .decodeFarcasterAttestation(a, 0, false)
            returns (uint256 attesterFid, address wallet) {
                if (attesterFid > 0) {
                    fid = attesterFid;
                    permissions =
                        FARCASTER_MEMBERSHIP_CAN_ATTEST |
                        FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER |
                        FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN;
                }
            } catch {}

            try
                IFarcasterResolverAttestationDecoder(address(schema.resolver))
                    .decodeFarcasterAttestation(a, 0, true)
            returns (uint256 revokerFid, address wallet) {
                if (revokerFid > 0 && (fid == revokerFid || fid == 0)) {
                    fid = revokerFid;
                    permissions =
                        permissions |
                        FARCASTER_MEMBERSHIP_CAN_REVOKE |
                        FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER |
                        FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN;
                }
            } catch {}

            if (fid == 0) {
                revert NoPrimaryFid(a.uid);
            }

            members[attUid].set(fid, permissions);

            bytes32 uid = _eas.attest(
                AttestationRequest({
                    schema: schemaId,
                    data: AttestationRequestData({
                        recipient: address(0),
                        expirationTime: 0,
                        revocable: true,
                        refUID: attUid,
                        data: abi.encode(fid, fid, permissions),
                        value: 0
                    })
                })
            );
            attestations[attUid][fid] = uid;

            emit SetMember(attUid, fid, fid, permissions);
        }
    }

    /**
     * @notice Verifies if a member has specific permissions
     * @param attUid The attestation UID
     * @param fid The Farcaster ID to check
     * @param permissions The permissions to verify
     * @return bool True if the member has all specified permissions
     */
    function verifyMember(
        bytes32 attUid,
        uint256 fid,
        uint256 permissions
    ) public virtual returns (bool) {
        initMember(attUid);

        if (!members[attUid].contains(fid)) return false;

        return hasPermission(members[attUid].get(fid), permissions);
    }

    /**
     * @notice Internal function to revoke an attestation
     * @param attUid The attestation UID
     * @param fid The Farcaster ID whose attestation should be revoked
     */
    function _revokeAttestation(bytes32 attUid, uint256 fid) internal {
        if (attestations[attUid][fid] != bytes32(0)) {
            _eas.revoke(
                RevocationRequest({
                    schema: schemaId,
                    data: RevocationRequestData({
                        uid: attestations[attUid][fid],
                        value: 0
                    })
                })
            );
            attestations[attUid][fid] = bytes32(0);
        }
    }

    /**
     * @notice Sets or updates a member's permissions
     * @param attUid The attestation UID
     * @param adminFid The Farcaster ID of the admin performing this action
     * @param memberFid The Farcaster ID of the member to update
     * @param permissions The new permission bitmask
     */
    function setMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid,
        uint256 permissions
    ) public virtual {
        if (permissions == 0) {
            return removeMember(attUid, adminFid, memberFid);
        }

        if (!verifier.isVerified(adminFid, msg.sender)) {
            revert PermissionDenied();
        }

        initMember(attUid);

        (bool adminJoined, uint256 adminPermissions) = getMember(
            attUid,
            adminFid
        );
        (, uint256 memberPermissions) = getMember(attUid, memberFid);

        _revokeAttestation(attUid, memberFid);

        if (
            !adminJoined ||
            (!hasPermission(
                adminPermissions,
                FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER
            ) &&
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN
                ))
        ) {
            revert PermissionDenied();
        }

        if (adminFid != memberFid) {
            if (
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN
                ) && permissions >= 8
            ) {
                revert PermissionDenied();
            }

            if (
                memberPermissions >= 8 &&
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN
                )
            ) {
                revert PermissionDenied();
            }
        } else {
            if (
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN
                ) && permissions >= 32
            ) {
                revert PermissionDenied();
            }
        }

        members[attUid].set(memberFid, permissions);

        bytes32 uid = _eas.attest(
            AttestationRequest({
                schema: schemaId,
                data: AttestationRequestData({
                    recipient: address(0),
                    expirationTime: 0,
                    revocable: true,
                    refUID: attUid,
                    data: abi.encode(adminFid, memberFid, permissions),
                    value: 0
                })
            })
        );
        attestations[attUid][memberFid] = uid;

        emit SetMember(attUid, adminFid, memberFid, permissions);
    }

    /**
     * @notice Removes a member from the membership
     * @param attUid The attestation UID
     * @param adminFid The Farcaster ID of the admin (or member themselves) performing this removal
     * @param memberFid The Farcaster ID of the member to remove
     */
    function removeMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid
    ) public {
        if (!verifier.isVerified(adminFid, msg.sender)) {
            revert PermissionDenied();
        }

        initMember(attUid);
        _revokeAttestation(attUid, memberFid);

        (bool adminJoined, uint256 adminPermissions) = getMember(
            attUid,
            adminFid
        );
        (bool memberJoined, uint256 memberPermissions) = getMember(
            attUid,
            memberFid
        );

        if (!adminJoined || !memberJoined) {
            revert PermissionDenied();
        }

        if (adminFid != memberFid) {
            if (
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER
                ) &&
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN
                )
            ) {
                revert PermissionDenied();
            }

            if (
                memberPermissions >= 8 &&
                !hasPermission(
                    adminPermissions,
                    FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN
                )
            ) {
                revert PermissionDenied();
            }
        }

        members[attUid].remove(memberFid);
        emit RemoveMember(attUid, adminFid, memberFid);
    }

    /**
     * @notice Callback for when an attestation is made
     * @param attestation The attestation being made
     * @return bool True if the attestation is valid
     */
    function onAttest(
        Attestation calldata attestation,
        uint256
    ) internal virtual override returns (bool) {
        return
            attestation.attester == address(this) &&
            attestation.schema == schemaId;
    }

    /**
     * @notice Callback for when an attestation is revoked
     * @param attestation The attestation being revoked
     * @return bool True if the revocation is valid
     */
    function onRevoke(
        Attestation calldata attestation,
        uint256
    ) internal virtual override returns (bool) {
        return
            attestation.attester == address(this) &&
            attestation.schema == schemaId;
    }
}
