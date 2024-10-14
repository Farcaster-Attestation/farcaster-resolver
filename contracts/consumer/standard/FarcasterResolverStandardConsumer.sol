// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SchemaRecord} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import "../../IFarcasterMembership.sol";
import "../FarcasterResolverConsumer.sol";
import "../IAttestationResolverRefDecoder.sol";

contract FarcasterResolverStandardConsumer is
    FarcasterResolverConsumer,
    IAttestationResolverRefDecoder
{
    IFarcasterMembership public immutable membership;
    bool immutable useRecipient;
    bool immutable useRefFid;
    bool immutable useRefCheck;
    bool immutable useRefBody;
    uint256 immutable fidOffset;
    uint256 immutable refOffset;

    error PermissionDenied();
    error RefNotFound(bytes32 uid);
    error MissingFarcasterResolverConsumer(bytes32 uid);
    error AttestationRevoked(bytes32 uid);

    constructor(
        IEAS _eas,
        IFarcasterVerification _resolver,
        IFarcasterMembership _membership,
        bool _useRecipient,
        bool _useRefFid,
        bool _useRefCheck,
        bool _useRefBody,
        uint256 _fidOffset,
        uint256 _refOffset
    ) FarcasterResolverConsumer(_eas, _resolver) {
        membership = _membership;
        useRecipient = _useRecipient;
        useRefFid = _useRefFid;
        useRefCheck = _useRefCheck;
        useRefBody = _useRefBody;
        fidOffset = _fidOffset;
        refOffset = _refOffset;
    }

    function decodeRefUid(
        Attestation calldata attestation,
        uint256 /*value*/,
        bool /*isRevoke*/
    ) public virtual returns (bytes32 uid) {
        if (useRefBody) {
            bytes calldata data = attestation.data;
            uint256 _refOffset = refOffset;
            assembly {
                uid := calldataload(add(data.offset, _refOffset))
            }
        } else {
            return attestation.refUID;
        }
    }

    function decodeRecursiveRefUid(
        Attestation memory attestation,
        uint256 value,
        bool isRevoke
    ) internal virtual returns (Attestation memory, SchemaRecord memory) {
        SchemaRecord memory schema = _eas.getSchemaRegistry().getSchema(
            attestation.schema
        );

        if (attestation.revocationTime > 0)
            revert AttestationRevoked(attestation.uid);

        if (
            address(schema.resolver) == address(0) ||
            !IERC165(address(schema.resolver)).supportsInterface(
                type(IFarcasterResolverAttestationDecoder).interfaceId
            )
        ) {
            if (attestation.refUID == bytes32(0)) {
                revert MissingFarcasterResolverConsumer(attestation.uid);
            } else {
                bytes32 refUid = attestation.refUID;

                if (
                    IERC165(address(schema.resolver)).supportsInterface(
                        type(IAttestationResolverRefDecoder).interfaceId
                    )
                ) {
                    refUid = IAttestationResolverRefDecoder(
                        address(schema.resolver)
                    ).decodeRefUid(attestation, value, isRevoke);
                }

                Attestation memory ref = _eas.getAttestation(refUid);
                return decodeRecursiveRefUid(ref, value, isRevoke);
            }
        }

        return (attestation, schema);
    }

    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) public virtual override returns (uint256 fid, address wallet) {
        if (useRecipient) {
            wallet = attestation.recipient;
        } else {
            wallet = attestation.attester;
        }

        if (useRefFid) {
            if (decodeRefUid(attestation, value, isRevoke) == bytes32(0)) {
                revert RefNotFound(attestation.uid);
            }

            (
                Attestation memory ref,
                SchemaRecord memory schema
            ) = decodeRecursiveRefUid(attestation, value, isRevoke);

            (fid, ) = IFarcasterResolverAttestationDecoder(
                address(schema.resolver)
            ).decodeFarcasterAttestation(ref, value, isRevoke);
        } else {
            bytes calldata data = attestation.data;
            uint256 _fidOffset = fidOffset;
            assembly {
                fid := calldataload(add(data.offset, _fidOffset))
            }
        }
    }

    function isValidAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    )
        public
        virtual
        override
        returns (bool valid, uint256 fid, address wallet)
    {
        // Check for farcaster ID <-> wallet verification
        (valid, fid, wallet) = super.isValidAttestation(
            attestation,
            value,
            isRevoke
        );

        // Check for permisison in reference attestation
        if (valid && useRefCheck) {
            if (decodeRefUid(attestation, value, isRevoke) == bytes32(0)) {
                revert RefNotFound(attestation.uid);
            }

            (
                Attestation memory ref,
            ) = decodeRecursiveRefUid(attestation, value, isRevoke);

            valid = membership.verifyMember(ref.uid, fid, isRevoke ? FARCASTER_MEMBERSHIP_CAN_REVOKE : FARCASTER_MEMBERSHIP_CAN_ATTEST);
        }
    }

    /**
     * @notice Checks if the contract supports a specific interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return `true` if the contract implements `interfaceId`
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == type(IAttestationResolverRefDecoder).interfaceId;
    }
}
