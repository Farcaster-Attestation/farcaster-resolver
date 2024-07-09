// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IFarcasterWalletVerifier {
    function verifyAdd(
        uint256 fid,
        address verifyAdrress,
        uint256 method,
        bytes memory signature
    ) external view returns (bool);

    function verifyRemove(
        uint256 fid,
        address verifyAdrress,
        uint256 method,
        bytes memory signature
    ) external view returns (bool);
}
