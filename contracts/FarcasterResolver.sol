// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterWalletVerifier} from "./wallet-verifier/IFarcasterWalletVerifier.sol";
import {FarcasterWalletVerifierRouter} from "./wallet-verifier/FarcasterWalletVerifierRouter.sol";

// (fid, verifyAddress, method, signature)

contract FarcasterResolver is SchemaResolver, FarcasterWalletVerifierRouter {
    // Mapping of key is the keccak256 hash of the farcaster id and the verifier address
    // The value is the attestation uid
    mapping(bytes32 => bytes32) public uid;

    /**
     * @dev Constructor for the FarcasterResolver contract
     * @param eas The Ethereum Attestation Service
     * @param admin The address of the admin
     */
    constructor(
        IEAS eas,
        address admin
    ) SchemaResolver(eas) FarcasterWalletVerifierRouter(admin) {}

    /**
     * @dev Emitted when a verification attestation is attested.
     * @param fid The Farcaster ID
     * @param verifyAddress The address being verified
     * @param verificationMethod The method used for verification
     * @param publicKey The public key associated with the attestation
     * @param signature The signature of the attestation
     */
    event VerificationAttested(
        uint256 indexed fid,
        address indexed verifyAddress,
        uint256 indexed verificationMethod,
        bytes32 publicKey,
        bytes signature
    );

    /**
     * @notice Attest a Farcaster ID and add the verified address to the mapping.
     * @dev Attests the provided attestation data.
     * @param attestation The attestation to add
     * @return bool indicating success of the attestation
     */
    function onAttest(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal override returns (bool) {
        (
            uint256 fid,
            bytes32 publicKey,
            uint256 verificationMethod,
            bytes memory signature
        ) = abi.decode(attestation.data, (uint256, bytes32, uint256, bytes));
        bytes32 key = computeKey(fid, attestation.recipient);
        if (uid[key] != bytes32(0)) {
            return false;
        }

        uid[key] = attestation.uid;

        emit VerificationAttested(
            fid,
            attestation.recipient,
            verificationMethod,
            publicKey,
            signature
        );

        return
            verifyAdd(
                fid,
                attestation.recipient,
                publicKey,
                verificationMethod,
                signature
            );
    }

    /**
     * @dev Emitted when a verification attestation is revoked.
     * @param fid The Farcaster ID
     * @param verifyAddress The address being verified
     * @param verificationMethod The method used for verification
     * @param publicKey The public key associated with the attestation
     * @param signature The signature of the attestation
     */
    event VerificationRevoked(
        uint256 indexed fid,
        address indexed verifyAddress,
        uint256 indexed verificationMethod,
        bytes32 publicKey,
        bytes signature
    );

    /**
     * @notice Revoke an attestation for a given Farcaster ID.
     * @dev Revokes the provided attestation data.
     * @param attestation The attestation to revoke
     * @return bool indicating success of the revocation
     */
    function onRevoke(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal override returns (bool) {
        (
            uint256 fid,
            bytes32 publicKey,
            uint256 verificationMethod,
            bytes memory signature
        ) = abi.decode(attestation.data, (uint256, bytes32, uint256, bytes));
        bytes32 key = computeKey(fid, attestation.recipient);
        if (uid[key] != attestation.uid) {
            return false;
        }

        delete uid[key];

        emit VerificationRevoked(
            fid,
            attestation.recipient,
            verificationMethod,
            publicKey,
            signature
        );

        return
            verifyRemove(
                fid,
                attestation.recipient,
                publicKey,
                verificationMethod,
                signature
            );
    }

    /**
     * @notice Compute the key used for mapping.
     * @dev Computes the key by hashing the Farcaster ID and verifier address.
     * @param _fid The Farcaster ID
     * @param _verifyAddr The verifier address
     * @return The computed key
     */
    function computeKey(
        uint256 _fid,
        address _verifyAddr
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_fid, _verifyAddr));
    }
}
