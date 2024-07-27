// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {IFarcasterWalletVerifier} from "./IFarcasterWalletVerifier.sol";
import {IFarcasterPublicKeyVerifier} from "../public-key-verifier/IFarcasterPublicKeyVerifier.sol";

contract FarcasterWalletVerifierRouter is AccessControl {
    /// @notice Role identifier for operator role (OptimismGovernor)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Role identifier for security role (Security Council)
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    /// @notice Mapping from method identifier to the corresponding wallet verifier contract
    mapping(uint256 => IFarcasterWalletVerifier) public verifiers;

    /// @notice Public key verifier contract
    IFarcasterPublicKeyVerifier public publicKeyVerifier;

    /**
     * @dev Event emitted when a verifier is set for a method.
     * @param method The method identifier.
     * @param verifier The address of the verifier contract.
     */
    event SetVerifier(uint256 indexed method, address verifier);

    /**
     * @dev Event emitted when the public key verifier is set.
     * @param verifier The address of the public key verifier contract.
     */
    event SetPublicKeyVerifier(address verifier);

    /**
     * @dev Constructor to set the initial admin role.
     * @param admin The address to be granted the admin role.
     */
    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
    }

    /**
     * @notice Sets the verifier contract for a specific method by operator.
     * @param method The method identifier.
     * @param verifier The address of the verifier contract.
     */
    function setVerifier(
        uint256 method,
        IFarcasterWalletVerifier verifier
    ) public onlyRole(OPERATOR_ROLE) {
        verifiers[method] = verifier;
        emit SetVerifier(method, address(verifier));
    }

    /**
     * @notice Sets the public key verifier contract by operator.
     * @param verifier The address of the public key verifier contract.
     */
    function setPublicKeyVerifier(
        IFarcasterPublicKeyVerifier verifier
    ) public onlyRole(OPERATOR_ROLE) {
        publicKeyVerifier = verifier;
        emit SetPublicKeyVerifier(address(verifier));
    }

    /**
     * @notice Removes the verifier contract for a specific method by security council in case of emergency.
     * @param method The method identifier.
     */
    function emergencyRemoveVerifier(
        uint256 method
    ) public onlyRole(SECURITY_ROLE) {
        delete verifiers[method];
        emit SetVerifier(method, address(0));
    }

    /**
     * @notice Verifies a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param method The method identifier for the verifier.
     * @param signature The signature to be verified.
     * @return bool indicating whether the verification was successful.
     */
    function verifyAdd(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        uint256 method,
        bytes memory signature
    ) public view returns (bool) {
        if (address(verifiers[method]) == address(0)) return false;

        if (!publicKeyVerifier.verifyPublicKey(fid, publicKey)) return false;

        return
            verifiers[method].verifyAdd(
                fid,
                verifyAddress,
                publicKey,
                signature
            );
    }

    /**
     * @notice Verifies the removal of a Farcaster wallet verification.
     * @param fid The Farcaster ID (FID) of the user.
     * @param verifyAddress The address to be verified.
     * @param publicKey The public key associated with the signature.
     * @param method The method identifier for the verifier.
     * @param signature The signature to be verified.
     * @return bool indicating whether the verification was successful.
     */
    function verifyRemove(
        uint256 fid,
        address verifyAddress,
        bytes32 publicKey,
        uint256 method,
        bytes memory signature
    ) public view returns (bool) {
        if (address(verifiers[method]) == address(0)) return false;

        if (!publicKeyVerifier.verifyPublicKey(fid, publicKey)) return false;

        return
            verifiers[method].verifyRemove(
                fid,
                verifyAddress,
                publicKey,
                signature
            );
    }
}
