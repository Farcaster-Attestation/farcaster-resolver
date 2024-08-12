// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterResolver} from "../IFarcasterResolver.sol";

// Assume first element of attestation body is fid and match against attester
contract FarcasterResolverConsumer is SchemaResolver {
    IFarcasterResolver public immutable resolver;

    constructor(IEAS eas, IFarcasterResolver _resolver) SchemaResolver(eas) {
        resolver = _resolver;
    }

    function isValidAttestation(Attestation calldata attestation) public virtual view returns (bool) {
        (uint256 fid) = abi.decode(attestation.data, (uint256));
        return resolver.isVerified(fid, attestation.attester);
    }

    // Assume first element of attestation body is fid and match against attester
    function onAttest(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal virtual override returns (bool) {
        return isValidAttestation(attestation);
    }

    // Assume first element of attestation body is fid and match against attester
    function onRevoke(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal virtual override returns (bool) {
        return isValidAttestation(attestation);
    }
}
