// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {FarcasterResolverDynamic} from "./FarcasterResolverDynamic.sol";
import {ClonesWithImmutableArgs} from "clones-with-immutable-args/src/ClonesWithImmutableArgs.sol";

contract FarcasterResolverDynamicFactory {
    using ClonesWithImmutableArgs for address;

    FarcasterResolverDynamic public implementation;

    constructor(FarcasterResolverDynamic implementation_) {
        implementation = implementation_;
    }

    function clone(
        address attestationDecoder
    ) external payable returns (FarcasterResolverDynamic resolver) {
        bytes memory data = abi.encodePacked(attestationDecoder);
        resolver = FarcasterResolverDynamic(address(implementation).clone2(data, msg.value));
    }

    function cloneAddress(
        address attestationDecoder
    ) external view returns (address resolver) {
        bytes memory data = abi.encodePacked(attestationDecoder);
        resolver = address(implementation).addressOfClone2(data);
    }
}