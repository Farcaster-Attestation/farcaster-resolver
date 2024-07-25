// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {IFarcasterWalletVerifier} from "./IFarcasterWalletVerifier.sol";
import {IFarcasterPublicKeyVerifier} from "../public-key-verifier/IFarcasterWalletVerifier.sol";

contract FarcasterWalletVerifierRouter is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    mapping(uint256 => IFarcasterWalletVerifier) public verifiers;
    IFarcasterPublicKeyVerifier public publicKeyVerifier;

    event SetVerifier(uint256 indexed method, address verifier);
    event SetPublicKeyVerifier(address verifier);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function setVerifier(
        uint256 method,
        IFarcasterWalletVerifier verifier
    ) public onlyRole(OPERATOR_ROLE) {
        verifiers[method] = verifier;
        emit SetVerifier(method, address(verifier));
    }

    function setPublicKeyVerifier(
        IFarcasterWalletVerifier verifier
    ) public onlyRole(OPERATOR_ROLE) {
        publicKeyVerifier = verifier;
        emit SetPublicKeyVerifier(address(verifier));
    }

    function emergencyRemoveVerifier(
        uint256 method
    ) public onlyRole(SECURITY_ROLE) {
        delete verifiers[method];
        emit SetVerifier(method, address(0));
    }

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
