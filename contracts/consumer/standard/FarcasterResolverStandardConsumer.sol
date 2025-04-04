// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SchemaRecord} from "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import {ERC165Checker} from "@openzeppelin/contracts/utils/introspection/ERC165Checker.sol";
import "../../IFarcasterMembership.sol";
import "../FarcasterResolverConsumer.sol";
import "../IFarcasterResolverRefDecoder.sol";

/**
 * @title FarcasterResolverStandardConsumer
 * @notice Standard consumer contract for decoding and validating Farcaster attestations with reference support
 * @dev Extends FarcasterResolverConsumer with reference attestation decoding and validation
 */
contract FarcasterResolverStandardConsumer is
    FarcasterResolverConsumer,
    IFarcasterResolverRefDecoder
{
    using ERC165Checker for address;

    /// @notice The Farcaster membership contract
    IFarcasterMembership public immutable membership;

    /// @notice Whether to use recipient instead of attester as wallet
    bool immutable useRecipient;

    /// @notice Whether to use FID from reference attestation
    bool immutable useRefFid;

    /// @notice Whether to check permissions in reference attestation
    bool immutable useRefCheck;

    /// @notice Whether to use reference UID from attestation body
    bool immutable useRefBody;

    /// @notice Offset of FID in attestation data
    uint256 immutable fidOffset;

    /// @notice Offset of reference UID in attestation data
    uint256 immutable refOffset;

    /// @notice Required attester address
    address immutable requiredAttester;

    /// @notice Error thrown when caller lacks required permissions
    error PermissionDenied();

    /// @notice Error thrown when reference attestation not found
    error RefNotFound(bytes32 uid);

    /// @notice Error thrown when resolver consumer not found
    error MissingFarcasterResolverConsumer(bytes32 uid);

    /// @notice Error thrown when attestation is revoked
    error AttestationRevoked(bytes32 uid);

    /// @notice Error thrown when attestation is expired
    error AttestationExpired(bytes32 uid);

    /// @notice Error thrown when attestation is from invalid required attester
    error InvalidAttester(bytes32 uid);

    /**
     * @notice Constructs the standard consumer contract
     * @param _eas The Ethereum Attestation Service contract
     * @param _resolver The Farcaster verification resolver contract
     * @param _membership The Farcaster membership contract
     * @param _useRecipient Whether to use recipient instead of attester as wallet
     * @param _useRefFid Whether to use FID from reference attestation
     * @param _useRefCheck Whether to check permissions in reference attestation
     * @param _useRefBody Whether to use reference UID from attestation body
     * @param _fidOffset Offset of FID in attestation data
     * @param _refOffset Offset of reference UID in attestation data
     * @param _requiredAttester The required attester address
     */
    constructor(
        IEAS _eas,
        IFarcasterVerification _resolver,
        IFarcasterMembership _membership,
        bool _useRecipient,
        bool _useRefFid,
        bool _useRefCheck,
        bool _useRefBody,
        uint256 _fidOffset,
        uint256 _refOffset,
        address _requiredAttester
    ) FarcasterResolverConsumer(_eas, _resolver) {
        membership = _membership;
        useRecipient = _useRecipient;
        useRefFid = _useRefFid;
        useRefCheck = _useRefCheck;
        useRefBody = _useRefBody;
        fidOffset = _fidOffset;
        refOffset = _refOffset;
        requiredAttester = _requiredAttester;
    }

    /**
     * @notice Decodes reference UID from attestation
     * @param attestation The attestation containing the reference
     * @param value The amount of ETH sent with the attestation
     * @param isRevoke Whether this is a revocation
     * @return uid The decoded reference UID
     */
    function decodeRefUid(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
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

    /**
     * @notice Recursively decodes reference attestation
     * @param attestation The attestation to decode
     * @param value Value parameter passed to the attestation
     * @param isRevoke Whether this is a revocation
     * @return Tuple containing decoded attestation and schema
     */
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
            attestation.expirationTime != 0 &&
            attestation.expirationTime < block.timestamp
        ) revert AttestationExpired(attestation.uid);

        bool supportsDecoderInterface = false;
        if (address(schema.resolver) != address(0)) {
            supportsDecoderInterface = address(schema.resolver)
                .supportsInterface(
                    type(IFarcasterResolverAttestationDecoder).interfaceId
                );
        }

        if (!supportsDecoderInterface) {
            bytes32 refUid;

            // Check if resolver supports IFarcasterResolverRefDecoder
            if (address(schema.resolver) != address(0)) {
                if (
                    address(schema.resolver).supportsInterface(
                        type(IFarcasterResolverRefDecoder).interfaceId
                    )
                ) {
                    // Use decodeRefUid if resolver supports it
                    refUid = IFarcasterResolverRefDecoder(
                        address(schema.resolver)
                    ).decodeRefUid(attestation, value, isRevoke);
                } else {
                    refUid = attestation.refUID;
                }
            } else {
                refUid = attestation.refUID;
            }

            if (refUid == bytes32(0)) {
                revert MissingFarcasterResolverConsumer(attestation.uid);
            } else {
                Attestation memory ref = _eas.getAttestation(refUid);
                return decodeRecursiveRefUid(ref, value, isRevoke);
            }
        }

        return (attestation, schema);
    }

    /**
     * @notice Decodes a Farcaster attestation to extract FID and wallet
     * @param attestation The attestation to decode
     * @param value Value parameter passed to the attestation
     * @param isRevoke Whether this is a revocation
     * @return fid The decoded Farcaster ID
     * @return wallet The decoded wallet address
     */
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

            Attestation memory firstRef = _eas.getAttestation(
                decodeRefUid(attestation, value, isRevoke)
            );

            (
                Attestation memory ref,
                SchemaRecord memory schema
            ) = decodeRecursiveRefUid(firstRef, value, isRevoke);

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

    /**
     * @notice Validates a Farcaster attestation
     * @param attestation The attestation to validate
     * @param value Value parameter passed to the attestation
     * @param isRevoke Whether this is a revocation
     * @return valid Whether the attestation is valid
     * @return fid The decoded Farcaster ID
     * @return wallet The decoded wallet address
     */
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
        if (
            requiredAttester != address(0) &&
            attestation.attester != requiredAttester
        ) {
            revert InvalidAttester(attestation.uid);
        }

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

            Attestation memory firstRef = _eas.getAttestation(
                decodeRefUid(attestation, value, isRevoke)
            );

            (Attestation memory ref, ) = decodeRecursiveRefUid(
                firstRef,
                value,
                isRevoke
            );

            if (ref.revocationTime > 0) revert AttestationRevoked(ref.uid);

            valid = membership.verifyMember(
                ref.uid,
                fid,
                isRevoke
                    ? FARCASTER_MEMBERSHIP_CAN_REVOKE
                    : FARCASTER_MEMBERSHIP_CAN_ATTEST
            );
        }
    }

    /**
     * @notice Checks if the contract supports a specific interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return bool `true` if the contract implements `interfaceId`
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override returns (bool) {
        return
            super.supportsInterface(interfaceId) ||
            interfaceId == type(IFarcasterResolverRefDecoder).interfaceId;
    }
}
