// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";
import {IFarcasterWalletVerifier} from "./IFarcasterWalletVerifier.sol";

contract FarcasterWalletVerifierRouter is AccessControl {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    mapping(uint256 => IFarcasterWalletVerifier) public verifiers;

    event SetVerifier(uint256 indexed method, address verifier);

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

    function emergencyRemoveVerifier(
        uint256 method
    ) public onlyRole(SECURITY_ROLE) {
        delete verifiers[method];
        emit SetVerifier(method, address(0));
    }

    function verifyAdd(
        uint256 fid,
        address verifyAdrress,
        uint256 method,
        bytes memory signature
    ) external view returns (bool) {
        if (address(verifiers[method]) == address(0)) return false;
        return
            verifiers[method].verifyAdd(fid, verifyAdrress, method, signature);
    }

    function verifyRemove(
        uint256 fid,
        address verifyAdrress,
        uint256 method,
        bytes memory signature
    ) external view returns (bool) {
        if (address(verifiers[method]) == address(0)) return false;
        return
            verifiers[method].verifyRemove(
                fid,
                verifyAdrress,
                method,
                signature
            );
    }
}