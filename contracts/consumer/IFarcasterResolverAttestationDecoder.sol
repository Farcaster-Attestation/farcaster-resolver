// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IFarcasterResolverAttestationDecoder
 * @notice Interface for decoding Farcaster attestations
 * @dev Used by resolver contracts that need to decode Farcaster-specific attestation data
 */
import {Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

interface IFarcasterResolverAttestationDecoder {
    /**
     * @notice Decodes a Farcaster attestation to extract FID and wallet
     * @param attestation The attestation to decode
     * @param value Value parameter passed to the attestation
     * @param isRevoke Whether this is a revocation
     * @return fid The decoded Farcaster ID
     * @return wallet The decoded wallet address
     */
    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) external returns (uint256 fid, address wallet);
}
