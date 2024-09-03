// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@ethereum-attestation-service/eas-contracts/contracts/ISchemaRegistry.sol";
import "./FarcasterResolverConsumer.sol";

contract FarcasterResolverRefConsumer is FarcasterResolverConsumer {
    error RefNotFound(bytes32 uid);
    error NotImplementedDecoder(bytes32 uid);

    constructor(
        IEAS eas,
        IFarcasterResolver _resolver
    ) FarcasterResolverConsumer(eas, _resolver) {}

    function _decodeFarcasterAttestation(
        Attestation memory attestation,
        uint256 value,
        bool isRevoke
    ) internal virtual returns (uint256 fid, address wallet) {
        SchemaRecord memory schema = _eas.getSchemaRegistry().getSchema(
            attestation.schema
        );

        if (
            address(schema.resolver) == address(0) ||
            !IERC165(address(schema.resolver)).supportsInterface(
                type(IFarcasterResolverAttestationDecoder).interfaceId
            )
        ) {
            if (attestation.refUID == bytes32(0)) {
                revert NotImplementedDecoder(attestation.uid);
            } else {
                Attestation memory ref = _eas.getAttestation(
                    attestation.refUID
                );
                return _decodeFarcasterAttestation(ref, value, isRevoke);
            }
        }

        return
            IFarcasterResolverAttestationDecoder(address(schema.resolver))
                .decodeFarcasterAttestation(attestation, value, isRevoke);
    }

    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) public virtual override returns (uint256 fid, address wallet) {
        if (attestation.refUID == bytes32(0)) {
            revert RefNotFound(attestation.uid);
        }

        Attestation memory ref = _eas.getAttestation(attestation.refUID);

        return _decodeFarcasterAttestation(ref, value, isRevoke);
    }
}
