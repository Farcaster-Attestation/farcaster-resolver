// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../FarcasterResolverConsumer.sol";

contract FarcasterResolverStandardConsumer is FarcasterResolverConsumer {
    bool immutable useRecipient;
    bool immutable useRefFid;
    bool immutable useRefCheck;
    uint256 immutable fidOffset;

    constructor(
        IEAS _eas,
        IFarcasterVerification _resolver,
        bool _useRecipient,
        bool _useRefFid,
        bool _useRefCheck,
        uint256 _fidOffset
    ) FarcasterResolverConsumer(_eas, _resolver) {
        useRecipient = _useRecipient;
        useRefFid = _useRefFid;
        useRefCheck = _useRefCheck;
        fidOffset = _fidOffset;
    }

    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 /*value*/,
        bool /*isRevoke*/
    ) public pure virtual override returns (uint256 fid, address wallet) {
        fid = abi.decode(attestation.data, (uint256));
        wallet = attestation.attester;
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
    }
}
