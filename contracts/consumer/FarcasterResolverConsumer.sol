// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterVerification} from "../IFarcasterResolver.sol";
import {IFarcasterResolverAttestationDecoder} from "./IFarcasterResolverAttestationDecoder.sol";

// Assume first element of attestation body is fid and match against attester
abstract contract FarcasterResolverConsumer is
    SchemaResolver,
    IFarcasterResolverAttestationDecoder,
    IERC165
{
    IFarcasterVerification public immutable resolver;

    constructor(
        IEAS eas,
        IFarcasterVerification _resolver
    ) SchemaResolver(eas) {
        resolver = _resolver;
    }

    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) public virtual returns (uint256 fid, address wallet);

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
        valid = resolver.isVerified(fid, wallet);
    }

    // Assume first element of attestation body is fid and match against attester
    function onAttest(
        Attestation calldata attestation,
        uint256 value
    ) internal virtual override returns (bool valid) {
        (valid,,) = isValidAttestation(attestation, value, false);
    }

    // Assume first element of attestation body is fid and match against attester
    function onRevoke(
        Attestation calldata attestation,
        uint256 value
    ) internal virtual override returns (bool valid) {
        (valid,,) = isValidAttestation(attestation, value, true);
    }

    /**
     * @notice Checks if the contract supports a specific interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return `true` if the contract implements `interfaceId`
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual returns (bool) {
        return
            interfaceId ==
            type(IFarcasterResolverAttestationDecoder).interfaceId;
    }
}
