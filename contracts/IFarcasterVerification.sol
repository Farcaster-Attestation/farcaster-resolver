// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IFarcasterVerification {
    /**
     * @notice Check if a wallet is verified for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @param wallet The wallet address.
     * @return bool indicating if the wallet is verified.
     */
    function isVerified(uint256 fid, address wallet) external view returns (bool);
}