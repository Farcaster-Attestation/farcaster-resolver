// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver, ISchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterVerification} from "../IFarcasterResolver.sol";
import {IFarcasterResolverAttestationDecoder} from "./IFarcasterResolverAttestationDecoder.sol";

/**
 * @title FarcasterResolverConsumer
 * @notice Base contract for consuming and validating Farcaster attestations
 * @dev Abstract contract that implements attestation decoding and validation logic
 */
abstract contract FarcasterResolverConsumer is
    SchemaResolver,
    IFarcasterResolverAttestationDecoder,
    IERC165
{
    /// @notice The Farcaster verification resolver contract
    IFarcasterVerification public immutable resolver;

    /**
     * @notice Constructs the consumer contract
     * @param eas The Ethereum Attestation Service contract
     * @param _resolver The Farcaster verification resolver contract
     */
    constructor(
        IEAS eas,
        IFarcasterVerification _resolver
    ) SchemaResolver(eas) {
        resolver = _resolver;
    }

    /**
     * @notice Decodes a Farcaster attestation to extract FID and wallet
     * @param attestation The attestation to decode
     * @param value The amount of ETH sent with the attestation
     * @param isRevoke Whether this is a revocation
     * @return fid The decoded Farcaster ID
     * @return wallet The decoded wallet address
     */
    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) public virtual returns (uint256 fid, address wallet);

    /**
     * @notice Validates a Farcaster attestation by checking if the FID and wallet are verified
     * @param attestation The attestation to validate
     * @param value The amount of ETH sent with the attestation
     * @param isRevoke Whether this is a revocation
     * @return valid Whether the attestation is valid
     * @return fid The decoded Farcaster ID
     * @return wallet The decoded wallet address
     */
    function isValidAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) public virtual returns (bool valid, uint256 fid, address wallet) {
        (fid, wallet) = decodeFarcasterAttestation(
            attestation,
            value,
            isRevoke
        );

        // Allow revocations from the attester, already checked in EAS
        if (isRevoke) {
            return (true, fid, wallet);
        }

        valid =
            (attestation.expirationTime == 0 ||
                attestation.expirationTime >= block.timestamp) &&
            resolver.isVerified(fid, wallet);
    }

    /**
     * @notice Validates an attestation during the attestation process
     * @dev Assumes first element of attestation body is FID and matches against attester
     * @param attestation The attestation to validate
     * @param value The amount of ETH sent with the attestation
     * @return valid Whether the attestation is valid
     */
    function onAttest(
        Attestation calldata attestation,
        uint256 value
    ) internal virtual override returns (bool valid) {
        (valid, , ) = isValidAttestation(attestation, value, false);
    }

    /**
     * @notice Validates an attestation during the revocation process
     * @dev Assumes first element of attestation body is FID and matches against attester
     * @param attestation The attestation to validate
     * @param value The amount of ETH sent with the attestation
     * @return valid Whether the attestation is valid
     */
    function onRevoke(
        Attestation calldata attestation,
        uint256 value
    ) internal virtual override returns (bool valid) {
        (valid, , ) = isValidAttestation(attestation, value, true);
    }

    /**
     * @notice Checks if the contract supports a specific interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return bool `true` if the contract implements `interfaceId`
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual returns (bool) {
        return
            interfaceId ==
            type(IFarcasterResolverAttestationDecoder).interfaceId ||
            interfaceId == type(IERC165).interfaceId ||
            interfaceId == type(ISchemaResolver).interfaceId;
    }
}
