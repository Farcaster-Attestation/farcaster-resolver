// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

/**
 * @title IFarcasterResolver
 * @notice Interface for Farcaster Resolver contract.
 */
interface IFarcasterResolver {

    /**
     * @dev Emitted when a verification attestation is attested.
     * @param fid The Farcaster ID.
     * @param verifyAddress The address being verified.
     * @param verificationMethod The method used for verification.
     * @param publicKey The public key associated with the attestation.
     * @param signature The signature of the attestation.
     */
    event VerificationAttested(
        uint256 indexed fid,
        address indexed verifyAddress,
        uint256 indexed verificationMethod,
        bytes32 publicKey,
        bytes signature
    );

    /**
     * @dev Emitted when a verification attestation is revoked.
     * @param fid The Farcaster ID.
     * @param verifyAddress The address being verified.
     * @param verificationMethod The method used for verification.
     * @param publicKey The public key associated with the attestation.
     * @param signature The signature of the attestation.
     */
    event VerificationRevoked(
        uint256 indexed fid,
        address indexed verifyAddress,
        uint256 indexed verificationMethod,
        bytes32 publicKey,
        bytes signature
    );

    /**
     * @notice Compute the key used for mapping.
     * @dev Computes the key by hashing the Farcaster ID and verifier address.
     * @param _fid The Farcaster ID.
     * @param _verifyAddr The verifier address.
     * @return The computed key.
     */
    function computeKey(
        uint256 _fid,
        address _verifyAddr
    ) external pure returns (bytes32);

    /**
     * @notice Get the attestation UID linked to the verification of a Farcaster ID and wallet address.
     * @param fid The Farcaster ID.
     * @param wallet The wallet address.
     * @return The attestation UID.
     */
    function getAttestationUid(uint256 fid, address wallet) external view returns (bytes32);

    /**
     * @notice Check if a wallet is verified for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @param wallet The wallet address.
     * @return bool indicating if the wallet is verified.
     */
    function isVerified(uint256 fid, address wallet) external view returns (bool);

    /**
     * @notice Get the number of attestations and verified FIDs for a given wallet address.
     * @param wallet The wallet address.
     * @return The number of attestations.
     */
    function walletAttestationsLength(address wallet) external view returns (uint256);

    /**
     * @notice Get the attestations and verified FIDs for a given wallet address, starting from a specific index.
     * @param wallet The wallet address.
     * @param start The starting index.
     * @param len The number of attestations to retrieve.
     * @return fids The Farcaster IDs.
     * @return uids The attestation UIDs.
     */
    function getWalletAttestations(
        address wallet,
        uint256 start,
        uint256 len
    ) external view returns (uint256[] memory fids, bytes32[] memory uids);

    /**
     * @notice Get all the attestations and verified FIDs for a given wallet address.
     * @param wallet The wallet address.
     * @return fids The Farcaster IDs.
     * @return uids The attestation UIDs.
     */
    function getWalletAttestations(
        address wallet
    ) external view returns (uint256[] memory fids, bytes32[] memory uids);

    /**
     * @notice Get the number of attestations and verified wallets for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @return The number of attestations.
     */
    function fidAttestationsLength(uint256 fid) external view returns (uint256);

    /**
     * @notice Get the attestations and verified wallets for a given Farcaster ID, starting from a specific index.
     * @param fid The Farcaster ID.
     * @param start The starting index.
     * @param len The number of attestations to retrieve.
     * @return wallets The wallet addresses.
     * @return uids The attestation UIDs.
     */
    function getFidAttestations(
        uint256 fid,
        uint256 start,
        uint256 len
    ) external view returns (address[] memory wallets, bytes32[] memory uids);

    /**
     * @notice Get all the attestations and verified wallets for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @return wallets The wallet addresses.
     * @return uids The attestation UIDs.
     */
    function getFidAttestations(
        uint256 fid
    ) external view returns (address[] memory wallets, bytes32[] memory uids);
}