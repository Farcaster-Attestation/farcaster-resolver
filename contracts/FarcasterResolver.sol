// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import { IEAS, Attestation } from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import { SchemaResolver } from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

contract FarcasterResolver is SchemaResolver {
    mapping(uint256 => address) public fidAttested;

   constructor(IEAS eas) SchemaResolver(eas) {}


    /// @dev Attest a farcaster id and add the verifier address to the mapping
    /// @param attestation The attestation to add
    function onAttest(Attestation calldata attestation, uint256 /*value*/) internal override returns (bool) {
        (uint256 fid, address verifyAdrress,) = abi.decode(attestation.data, (uint256, address, uint8));
        if (verifyAdrress == fidAttested[fid]) {
            return false;
        }

        fidAttested[fid] = verifyAdrress;

        return true;
    }

    /// @dev Revoke an attestation for a given farcaster id
    /// @param attestation The attestation to revoke
    function onRevoke(Attestation calldata attestation, uint256 /*value*/) internal override returns (bool) {
       (uint256 fid, address verifyAdrress,) = abi.decode(attestation.data, (uint256, address, uint8));
        if (verifyAdrress != fidAttested[fid]) {
            return false;
        }

        delete fidAttested[fid];

        return true;
    }
}