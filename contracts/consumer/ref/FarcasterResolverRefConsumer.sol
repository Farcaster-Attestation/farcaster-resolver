// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../standard/FarcasterResolverStandardConsumer.sol";

contract FarcasterResolverRefConsumer is FarcasterResolverStandardConsumer {
    constructor(
        IEAS eas,
        IFarcasterVerification _resolver
    )
        FarcasterResolverStandardConsumer(
            eas,
            _resolver,
            IFarcasterMembership(address(0)),
            false,
            true,
            false,
            false,
            0,
            0
        )
    {}
}