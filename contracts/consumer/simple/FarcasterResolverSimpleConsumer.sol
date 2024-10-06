// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../FarcasterResolverConsumer.sol";

contract FarcasterResolverSimpleConsumer is FarcasterResolverConsumer {
    constructor(IEAS eas, IFarcasterVerification _resolver) FarcasterResolverConsumer(eas, _resolver) {}

    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 /*value*/,
        bool /*isRevoke*/
    ) public virtual override pure returns (uint256 fid, address wallet) {
        fid = abi.decode(attestation.data, (uint256));
        wallet = attestation.attester;
    }
}