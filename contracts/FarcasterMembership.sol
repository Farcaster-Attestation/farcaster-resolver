// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {SchemaRecord} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IFarcasterResolverAttestationDecoder} from "./consumer/IFarcasterResolverAttestationDecoder.sol";
import "./IFarcasterMembership.sol";

// Permissions
uint256 constant FARCASTER_MEMBERSHIP_CAN_ATTEST = 1 << 0;
uint256 constant FARCASTER_MEMBERSHIP_CAN_LEAVE = 1 << 1;
uint256 constant FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER = 1 << 2;
uint256 constant FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER = 1 << 3;
uint256 constant FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN = 1 << 4;
uint256 constant FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN = 1 << 5;

contract FarcasterMembership is IFarcasterMembership, SchemaResolver {
    using EnumerableMap for EnumerableMap.UintToUintMap;

    error PermissionDenied();
    error MissingFarcasterResolverConsumer(bytes32 uid);
    error AttestationRevoked(bytes32 uid);

    IFarcasterVerification public immutable verifier;
    bytes32 public schemaId;
    mapping(bytes32 => EnumerableMap.UintToUintMap) members;

    constructor(
        IEAS eas,
        IFarcasterVerification _verifier
    ) SchemaResolver(eas) {
        verifier = _verifier;
    }

    function decodePackedMembership(
        uint256 input
    ) internal pure returns (uint128 farcasterId, uint128 permissions) {
        // Extract the lower 128 bits
        farcasterId = uint128(input & type(uint128).max);
        // Extract the upper 128 bits by shifting right
        permissions = uint128(input >> 128);
    }

    function hasPermission(
        uint256 permissions,
        uint256 flag
    ) internal pure returns (bool) {
        return (permissions & flag) > 0;
    }

    function getMember(
        bytes32 attUid,
        uint256 farcasterId
    ) public view returns (bool joined, uint256 permissions) {
        return members[attUid].tryGet(farcasterId);
    }

    function countMembers(bytes32 attUid) public view returns (uint256) {
        return members[attUid].length();
    }

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

    function initMember(bytes32 attUid, bool isRevoke) internal {
        Attestation memory a = _eas.getAttestation(attUid);
        SchemaRecord memory schema = _eas.getSchemaRegistry().getSchema(
            a.schema
        );

        if (a.revocationTime > 0) revert AttestationRevoked(a.uid);

        if (members[attUid].length() == 0) {
            if (
                address(schema.resolver) == address(0) ||
                !IERC165(address(schema.resolver)).supportsInterface(
                    type(IFarcasterResolverAttestationDecoder).interfaceId
                )
            ) {
                revert MissingFarcasterResolverConsumer(attUid);
            }

            (uint256 fid, ) = IFarcasterResolverAttestationDecoder(address(schema.resolver)).decodeFarcasterAttestation(a, 0, isRevoke);
            members[attUid].set(fid, 63);
            emit SetMember(attUid, 0, fid, 63);
        }
    }

    function setMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid,
        uint256 permissions
    ) public {
        initMember(attUid, false);

        (bool adminJoined, uint256 adminPermissions) = getMember(
            attUid,
            adminFid
        );

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

        if (
            !hasPermission(
                adminPermissions,
                FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN
            ) && permissions >= 4
        ) {
            revert PermissionDenied();
        }

        members[attUid].set(memberFid, permissions);
        emit SetMember(attUid, adminFid, memberFid, permissions);
    }

    function removeMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid
    ) public {
        initMember(attUid, true);

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

        if (
            adminFid == memberFid &&
            !hasPermission(adminPermissions, FARCASTER_MEMBERSHIP_CAN_LEAVE)
        ) {
            revert PermissionDenied();
        }

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
            memberPermissions >= 4 &&
            !hasPermission(
                adminPermissions,
                FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN
            )
        ) {
            revert PermissionDenied();
        }

        members[attUid].remove(memberFid);
        emit RemoveMember(attUid, adminFid, memberFid);
    }

    function onAttest(
        Attestation calldata attestation,
        uint256
    ) internal virtual override returns (bool) {
        return attestation.attester == address(this);
    }

    function onRevoke(
        Attestation calldata attestation,
        uint256
    ) internal virtual override returns (bool) {
        return attestation.attester == address(this);
    }
}
