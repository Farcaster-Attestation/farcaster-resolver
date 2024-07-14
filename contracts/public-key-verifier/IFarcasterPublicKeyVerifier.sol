// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IFarcasterPublicKeyVerifier {
    function verifyPublicKey(
        uint256 fid,
        bytes32 publicKey
    ) external view returns (bool);
}
