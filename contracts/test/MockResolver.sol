// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEAS, Attestation} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";
import {SchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MockResolver is SchemaResolver {
    constructor(IEAS eas) SchemaResolver(eas) {}

    function onAttest(
        Attestation calldata attestation,
        uint256 value
    ) internal view override returns (bool) {
        return true;
    }

    function onRevoke(
        Attestation calldata attestation,
        uint256 value
    ) internal view override returns (bool) {
        return true;
    }
}
