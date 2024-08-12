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
    ) external payable returns (FarcasterResolverDynamic clone) {
        bytes memory data = abi.encodePacked(attestationDecoder);
        clone = FarcasterResolverDynamic(address(implementation).clone2(data, msg.value));
    }

    function cloneAddress(
        address attestationDecoder
    ) external view returns (address clone) {
        bytes memory data = abi.encodePacked(attestationDecoder);
        clone = address(implementation).addressOfClone2(data);
    }
}