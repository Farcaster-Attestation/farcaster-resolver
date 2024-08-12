// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

interface IFarcasterResolverAttestationDecoder {
    function decodeFid(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) external returns (uint256 fid);

    function decodeWallet(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) external returns (address wallet);
}
