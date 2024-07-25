// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./IFarcasterWalletVerifier.sol";

contract FarcasterWalletOnchainVerifier is IFarcasterWalletVerifier {
    function verifyAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        uint256 method,
        bytes memory signature
    ) external view returns (bool) {
        
    }

    function verifyRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        uint256 method,
        bytes memory signature
    ) external view returns (bool) {
        
    }
}