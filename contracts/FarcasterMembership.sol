// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {SchemaResolver, ISchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaRecord} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IFarcasterResolverAttestationDecoder} from "./consumer/IFarcasterResolverAttestationDecoder.sol";
import "./IFarcasterMembership.sol";

contract FarcasterMembership is IFarcasterMembership, SchemaResolver, Multicall {
    using EnumerableMap for EnumerableMap.UintToUintMap;

    error PermissionDenied();
    error MissingFarcasterResolverConsumer(bytes32 uid);
    error AttestationRevoked(bytes32 uid);
    error NoPrimaryFid(bytes32 uid);

    IFarcasterVerification public immutable verifier;
    bytes32 public schemaId;
    mapping(bytes32 => EnumerableMap.UintToUintMap) members;
    mapping(bytes32 => mapping(uint256 => bytes32)) public attestations;

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
    ) internal virtual pure returns (bool) {
        return (permissions & flag) == flag;
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

    function initMember(bytes32 attUid) internal virtual {
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

            uint256 fid;
            uint256 permissions = 0; // 63 = 0b111111 can do everything

            // Fetch the primary member who can attest
            try IFarcasterResolverAttestationDecoder(address(schema.resolver)).decodeFarcasterAttestation(a, 0, false) returns (uint256 attesterFid, address wallet) {
                if (attesterFid > 0) {
                    fid = attesterFid;
                    permissions = FARCASTER_MEMBERSHIP_CAN_ATTEST | FARCASTER_MEMBERSHIP_CAN_ADD_MEMBER | FARCASTER_MEMBERSHIP_CAN_ADD_ADMIN;
                }
            } catch {}
            
            // Fetch the primary member who can revoke
            try IFarcasterResolverAttestationDecoder(address(schema.resolver)).decodeFarcasterAttestation(a, 0, true) returns (uint256 revokerFid, address wallet) {
                if (revokerFid > 0 && (fid == revokerFid || fid == 0)) {
                    fid = revokerFid;
                    permissions = permissions | FARCASTER_MEMBERSHIP_CAN_REVOKE | FARCASTER_MEMBERSHIP_CAN_LEAVE | FARCASTER_MEMBERSHIP_CAN_REMOVE_MEMBER | FARCASTER_MEMBERSHIP_CAN_REMOVE_ADMIN;
                }
            } catch {}

            if (fid == 0) {
                revert NoPrimaryFid(a.uid);
            }
            
            members[attUid].set(fid, permissions);
            emit SetMember(attUid, 0, fid, permissions);
        }
    }

    function verifyMember(bytes32 attUid, uint256 fid, uint256 permissions) public virtual returns(bool) {
        initMember(attUid);

        if (!members[attUid].contains(fid)) return false;

        return hasPermission(members[attUid].get(fid), permissions);
    }

    function _revokeAttestation(bytes32 attUid, uint256 fid) internal {
        if (attestations[attUid][fid] != bytes32(0)) {
            _eas.revoke(RevocationRequest({
                schema: schemaId,
                data: RevocationRequestData({
                    uid: attestations[attUid][fid],
                    value: 0
                })
            }));
            attestations[attUid][fid] = bytes32(0);
        }
    }

    function setMember(
        bytes32 attUid,
        uint256 adminFid,
        uint256 memberFid,
        uint256 permissions
    ) public virtual {
        if (!verifier.isVerified(adminFid, msg.sender)) {
            revert PermissionDenied();
        }

        initMember(attUid);
        _revokeAttestation(attUid, memberFid);

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

        bytes32 uid = _eas.attest(AttestationRequest({
            schema: schemaId,
            data: AttestationRequestData({
                recipient: msg.sender,
                expirationTime: 0,
                revocable: true,
                refUID: attUid,
                data: abi.encode(adminFid, memberFid, permissions),
                value: 0
            })
        }));
        attestations[attUid][memberFid] = uid;

        emit SetMember(attUid, adminFid, memberFid, permissions);
    }

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
        return attestation.attester == address(this) && attestation.schema == schemaId;
    }

    function onRevoke(
        Attestation calldata attestation,
        uint256
    ) internal virtual override returns (bool) {
        return attestation.attester == address(this) && attestation.schema == schemaId;
    }
}
