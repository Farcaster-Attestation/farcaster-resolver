// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./FarcasterResolverRefConsumer.sol";

contract FarcasterResolverSimpleRefConsumer is FarcasterResolverRefConsumer {
    constructor(
        IEAS eas,
        IFarcasterVerification _resolver
    ) FarcasterResolverRefConsumer(eas, _resolver) {}

    function decodeRef(
        Attestation memory attestation,
        uint256,
        bool
    ) public virtual override returns (bytes32 refUID) {
        return attestation.refUID;
    }
}