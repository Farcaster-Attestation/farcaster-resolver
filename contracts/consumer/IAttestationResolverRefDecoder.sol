// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title IAttestationResolverRefDecoder
 * @notice Interface for decoding reference UIDs from attestations
 * @dev Used by resolver contracts that need to decode reference attestation UIDs
 */
import {Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

interface IAttestationResolverRefDecoder {
    /**
     * @notice Decodes a reference UID from an attestation
     * @param attestation The attestation containing the reference
     * @param value Value parameter passed to the attestation
     * @param isRevoke Whether this is a revocation
     * @return uid The decoded reference UID
     */
    function decodeRefUid(
        Attestation calldata attestation,
        uint256 value,
        bool isRevoke
    ) external returns (bytes32 uid);
}
