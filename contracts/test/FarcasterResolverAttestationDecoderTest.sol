// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../consumer/IFarcasterResolverAttestationDecoder.sol";

contract FarcasterResolverAttestationDecoderTest is IFarcasterResolverAttestationDecoder {
    error InvalidValue();

    function decodeFid(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) external pure returns (uint256 fid) {
        if (!isRevoke && value != 10) revert InvalidValue();
        if (isRevoke && value != 1000) revert InvalidValue();

        (, fid) = abi.decode(attestation.data, (address, uint256));
    }

    function decodeWallet(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) external pure returns (address wallet) {
        if (!isRevoke && value != 10) revert InvalidValue();
        if (isRevoke && value != 1000) revert InvalidValue();

        (wallet) = abi.decode(attestation.data, (address));
    }
}