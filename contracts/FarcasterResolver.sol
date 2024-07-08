// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { IEAS, Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

contract FarcasterResolver is SchemaResolver {
    // Mapping of key is the keccak256 hash of the farcaster id and the verifier address
    // The value is the attestation uid
    mapping(bytes32 => bytes32) public fidAttested;

   constructor(IEAS eas) SchemaResolver(eas) {}


    /// @dev Attest a farcaster id and add the verifier address to the mapping
    /// @param attestation The attestation to add
    function onAttest(Attestation calldata attestation, uint256 /*value*/) internal override returns (bool) {
        (uint256 fid, address verifyAdrress,) = abi.decode(attestation.data, (uint256, address, uint8));
        bytes32 key = computeKey(fid, verifyAdrress);
        if (bytes32(0) == fidAttested[key]) {
            return false;
        }

        fidAttested[key] = attestation.uid;

        return true;
    }

    /// @dev Revoke an attestation for a given farcaster id
    /// @param attestation The attestation to revoke
    function onRevoke(Attestation calldata attestation, uint256 /*value*/) internal override returns (bool) {
       (uint256 fid, address verifyAdrress,) = abi.decode(attestation.data, (uint256, address, uint8));
        bytes32 key = computeKey(fid, verifyAdrress);
        if (attestation.uid != fidAttested[key]) {
            return false;
        }

        delete fidAttested[key];

        return true;
    }


    function computeKey(uint256 _fid, address _verifyAddr) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_fid, _verifyAddr));
    }
}