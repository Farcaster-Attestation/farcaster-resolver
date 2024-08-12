// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterResolver} from "../IFarcasterResolver.sol";
import {IFarcasterResolverAttestationDecoder} from "./IFarcasterResolverAttestationDecoder.sol";
import {Clone} from "clones-with-immutable-args/src/Clone.sol";

contract FarcasterResolverDynamic is SchemaResolver, Clone {
    IFarcasterResolver public immutable resolver;

    constructor(IEAS eas, IFarcasterResolver _resolver) SchemaResolver(eas) {
        resolver = _resolver;
    }

    function attestationDecoder() public pure returns (IFarcasterResolverAttestationDecoder) {
        return IFarcasterResolverAttestationDecoder(_getArgAddress(0));
    }

    function onAttest(
        Attestation calldata attestation,
        uint256 value
    ) internal virtual override returns (bool) {
        IFarcasterResolverAttestationDecoder decoder = attestationDecoder();
        uint256 fid = decoder.decodeFid(attestation, value, false);
        address wallet = decoder.decodeWallet(attestation, value, false);
        return resolver.isVerified(fid, wallet);
    }

    function onRevoke(
        Attestation calldata attestation,
        uint256 value
    ) internal virtual override returns (bool) {
        IFarcasterResolverAttestationDecoder decoder = attestationDecoder();
        uint256 fid = decoder.decodeFid(attestation, value, true);
        address wallet = decoder.decodeWallet(attestation, value, true);
        return resolver.isVerified(fid, wallet);
    }
}
