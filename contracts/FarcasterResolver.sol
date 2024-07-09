// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterWalletVerifier} from "./wallet-verifier/IFarcasterWalletVerifier.sol";

// (fid, verifyAddress, method, signature)

contract FarcasterResolver is SchemaResolver {
    IFarcasterWalletVerifier public immutable verifier;

    // Mapping of key is the keccak256 hash of the farcaster id and the verifier address
    // The value is the attestation uid
    mapping(bytes32 => bytes32) public uid;

    constructor(
        IEAS eas,
        IFarcasterWalletVerifier farcasterVerifier
    ) SchemaResolver(eas) {
        verifier = farcasterVerifier;
    }

    /// @dev Attest a farcaster id and add the verifier address to the mapping
    /// @param attestation The attestation to add
    function onAttest(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal override returns (bool) {
        (
            uint256 fid,
            address verifyAdrress,
            uint256 method,
            bytes memory signature
        ) = abi.decode(attestation.data, (uint256, address, uint256, bytes));
        bytes32 key = computeKey(fid, verifyAdrress);
        if (uid[key] != bytes32(0)) {
            return false;
        }

        uid[key] = attestation.uid;

        return verifier.verifyAdd(fid, verifyAdrress, method, signature);
    }

    /// @dev Revoke an attestation for a given farcaster id
    /// @param attestation The attestation to revoke
    function onRevoke(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal override returns (bool) {
        (
            uint256 fid,
            address verifyAdrress,
            uint256 method,
            bytes memory signature
        ) = abi.decode(attestation.data, (uint256, address, uint256, bytes));
        bytes32 key = computeKey(fid, verifyAdrress);
        if (uid[key] != attestation.uid) {
            return false;
        }

        delete uid[key];

        return verifier.verifyRemove(fid, verifyAdrress, method, signature);
    }

    function computeKey(
        uint256 _fid,
        address _verifyAddr
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_fid, _verifyAddr));
    }
}
