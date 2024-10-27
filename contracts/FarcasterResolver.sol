// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import {IEAS, Attestation, AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver, ISchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {IFarcasterWalletVerifier} from "./wallet-verifier/IFarcasterWalletVerifier.sol";
import {FarcasterWalletVerifierRouter} from "./wallet-verifier/FarcasterWalletVerifierRouter.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import "./IFarcasterResolver.sol";

// (fid, verifyAddress, method, signature)

contract FarcasterResolver is
    SchemaResolver,
    FarcasterWalletVerifierRouter,
    IFarcasterResolver,
    Multicall
{
    using EnumerableMap for EnumerableMap.UintToAddressMap;
    using EnumerableMap for EnumerableMap.UintToUintMap;

    /// @notice The schema ID for the Farcaster resolver
    bytes32 public schemaId;

    // Mapping of key is the keccak256 hash of the farcaster id and the verifier address
    // The value is the attestation uid
    mapping(bytes32 => bytes32) internal uid;

    mapping(address => EnumerableMap.UintToUintMap) internal walletAttestations;
    mapping(uint256 => EnumerableMap.UintToAddressMap) internal fidAttestations;

    /**
     * @dev Constructor for the FarcasterResolver contract
     * @param eas The Ethereum Attestation Service
     * @param admin The address of the admin
     */
    constructor(
        IEAS eas,
        address admin
    ) SchemaResolver(eas) FarcasterWalletVerifierRouter(admin) {
        schemaId = eas.getSchemaRegistry().register(
            "uint256 fid,bytes32 publicKey,uint256 verificationMethod,bytes memory signature",
            ISchemaResolver(address(this)),
            true
        );
    }

    /**
     * @notice Attest a Farcaster ID and add the verified address to the mapping.
     * @param recipient The recipient of the attestation
     * @param fid The Farcaster ID
     * @param publicKey The public key
     * @param verificationMethod The verification method
     * @param signature The signature
     */
    function attest(
        address recipient,
        uint256 fid,
        bytes32 publicKey,
        uint256 verificationMethod,
        bytes memory signature
    ) public returns (bytes32) {
        return
            _eas.attest(
                AttestationRequest({
                    schema: schemaId,
                    data: AttestationRequestData({
                        recipient: recipient,
                        expirationTime: 0,
                        revocable: true,
                        refUID: bytes32(0),
                        data: abi.encode(
                            fid,
                            publicKey,
                            verificationMethod,
                            signature
                        ),
                        value: 0
                    })
                })
            );
    }

    function revoke(
        address recipient,
        uint256 fid,
        bytes32 publicKey,
        uint256 verificationMethod,
        bytes memory signature
    ) public returns (bool) {
        bytes32 key = computeKey(fid, recipient);

        if (uid[key] == bytes32(0)) {
            return false;
        }

        bytes32 attUid = uid[key];

        walletAttestations[recipient].remove(uint256(attUid));
        fidAttestations[fid].remove(uint256(attUid));

        if (
            verifyRemove(
                fid,
                recipient,
                publicKey,
                verificationMethod,
                signature
            )
        ) {
            _eas.revoke(
                RevocationRequest({
                    schema: schemaId,
                    data: RevocationRequestData({uid: attUid, value: 0})
                })
            );

            delete uid[key];

            emit VerificationRevoked(
                fid,
                recipient,
                verificationMethod,
                publicKey,
                signature
            );

            return true;
        }

        return false;
    }

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
        if (
            attestation.attester != address(this) ||
            attestation.schema != schemaId
        ) {
            return false;
        }

        address recipient = attestation.recipient;

        (
            uint256 fid,
            bytes32 publicKey,
            uint256 verificationMethod,
            bytes memory signature
        ) = abi.decode(attestation.data, (uint256, bytes32, uint256, bytes));
        bytes32 key = computeKey(fid, recipient);
        if (uid[key] != bytes32(0)) {
            return false;
        }

        uid[key] = attestation.uid;
        walletAttestations[recipient].set(uint256(attestation.uid), fid);
        fidAttestations[fid].set(uint256(attestation.uid), recipient);

        emit VerificationAttested(
            fid,
            recipient,
            verificationMethod,
            publicKey,
            signature
        );

        return
            verifyAdd(fid, recipient, publicKey, verificationMethod, signature);
    }

    /**
     * @notice Revoke an attestation for a given Farcaster ID.
     * @dev Revokes the provided attestation data.
     * @param attestation The attestation to revoke
     * @return bool indicating success of the revocation
     */
    function onRevoke(
        Attestation calldata attestation,
        uint256 /*value*/
    ) internal override view returns (bool) {
        if (
            attestation.attester != address(this) ||
            attestation.schema != schemaId
        ) {
            return false;
        }

        return true;
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

    /**
     * @notice Get the attestation UID linked to the verification of a Farcaster ID and wallet address.
     * @param fid The Farcaster ID.
     * @param wallet The wallet address.
     * @return The attestation UID.
     */
    function getAttestationUid(
        uint256 fid,
        address wallet
    ) public view returns (bytes32) {
        bytes32 key = computeKey(fid, wallet);
        return uid[key];
    }

    /**
     * @notice Check if a wallet is verified for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @param wallet The wallet address.
     * @return bool indicating if the wallet is verified.
     */
    function isVerified(
        uint256 fid,
        address wallet
    ) public view returns (bool) {
        return getAttestationUid(fid, wallet) != bytes32(0);
    }

    /**
     * @notice Get the number of attestations and verified FIDs for a given wallet address.
     * @param wallet The wallet address.
     * @return The number of attestations.
     */
    function walletAttestationsLength(
        address wallet
    ) public view returns (uint256) {
        return walletAttestations[wallet].length();
    }

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
    ) public view returns (uint256[] memory fids, bytes32[] memory uids) {
        fids = new uint256[](len);
        uids = new bytes32[](len);

        for (uint256 i; i < len; ) {
            (uint256 u, uint256 f) = walletAttestations[wallet].at(start + i);

            fids[i] = f;
            uids[i] = bytes32(u);

            unchecked {
                i++;
            }
        }
    }

    /**
     * @notice Get all the attestations and verified FIDs for a given wallet address.
     * @param wallet The wallet address.
     * @return fids The Farcaster IDs.
     * @return uids The attestation UIDs.
     */
    function getWalletAttestations(
        address wallet
    ) public view returns (uint256[] memory fids, bytes32[] memory uids) {
        return
            getWalletAttestations(wallet, 0, walletAttestationsLength(wallet));
    }

    /**
     * @notice Get the number of attestations and verified wallets for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @return The number of attestations.
     */
    function fidAttestationsLength(uint256 fid) public view returns (uint256) {
        return fidAttestations[fid].length();
    }

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
    ) public view returns (address[] memory wallets, bytes32[] memory uids) {
        wallets = new address[](len);
        uids = new bytes32[](len);

        for (uint256 i; i < len; ) {
            (uint256 u, address w) = fidAttestations[fid].at(start + i);

            wallets[i] = w;
            uids[i] = bytes32(u);

            unchecked {
                i++;
            }
        }
    }

    /**
     * @notice Get all the attestations and verified wallets for a given Farcaster ID.
     * @param fid The Farcaster ID.
     * @return wallets The wallet addresses.
     * @return uids The attestation UIDs.
     */
    function getFidAttestations(
        uint256 fid
    ) public view returns (address[] memory wallets, bytes32[] memory uids) {
        return getFidAttestations(fid, 0, fidAttestationsLength(fid));
    }
}
