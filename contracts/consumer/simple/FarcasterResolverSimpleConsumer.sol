// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title FarcasterResolverSimpleConsumer
 * @notice A simple consumer contract for decoding Farcaster attestations
 * @dev Extends FarcasterResolverConsumer with basic attestation decoding functionality
 */
import "../standard/FarcasterResolverStandardConsumer.sol";

contract FarcasterResolverSimpleConsumer is FarcasterResolverConsumer {
    /**
     * @notice Constructs the simple consumer contract
     * @param eas The Ethereum Attestation Service contract
     * @param _resolver The Farcaster verification resolver contract
     */
    constructor(
        IEAS eas,
        IFarcasterVerification _resolver
    ) FarcasterResolverConsumer(eas, _resolver) {}

    /**
     * @notice Decodes a Farcaster attestation to extract the FID and wallet
     * @param attestation The attestation to decode
     * @param value The amount of ETH sent with the attestation
     * @param isRevoke Whether this is a revocation
     * @return fid The decoded Farcaster ID
     * @return wallet The decoded wallet address
     */
    function decodeFarcasterAttestation(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) public pure virtual override returns (uint256 fid, address wallet) {
        fid = abi.decode(attestation.data, (uint256));
        wallet = attestation.attester;
    }
}
