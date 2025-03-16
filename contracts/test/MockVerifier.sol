// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {EAS, IEAS} from "@ethereum-attestation-service/eas-contracts/contracts/EAS.sol";
import {SchemaRegistry, ISchemaRegistry} from "@ethereum-attestation-service/eas-contracts/contracts/SchemaRegistry.sol";
import {SchemaResolver, ISchemaResolver} from "@ethereum-attestation-service/eas-contracts/contracts/resolver/SchemaResolver.sol";

import {AttestationRequest, AttestationRequestData, RevocationRequest, RevocationRequestData} from "@ethereum-attestation-service/eas-contracts/contracts/IEAS.sol";

import {IFarcasterVerification} from "../IFarcasterVerification.sol";
import {IFarcasterMembership} from "../IFarcasterMembership.sol";
import {IFarcasterWalletVerifier} from "../wallet-verifier/IFarcasterWalletVerifier.sol";
import {IFarcasterPublicKeyVerifier} from "../public-key-verifier/IFarcasterPublicKeyVerifier.sol";
import {FarcasterResolver} from "../FarcasterResolver.sol";
import {FarcasterMembership} from "../FarcasterMembership.sol";
import {FarcasterResolverSimpleConsumer} from "../consumer/simple/FarcasterResolverSimpleConsumer.sol";

contract MockPublicKeyVerifier is IFarcasterPublicKeyVerifier {
    bool private returnValue;

    function setReturnValue(bool _returnValue) public {
        returnValue = _returnValue;
    }

    function verifyPublicKey(uint256, bytes32) external view returns (bool) {
        return returnValue;
    }
}

contract MockWalletVerifier is IFarcasterWalletVerifier {
    uint256 private returnValue;

    function setReturnValue(bool _returnValue) public {
        if (_returnValue) {
            returnValue = block.timestamp - 1609459200;
        } else {
            returnValue = 0;
        }
    }

    function verifyAdd(
        uint256,
        address,
        bytes32,
        bytes memory
    ) external view returns (uint256) {
        return returnValue;
    }

    function verifyRemove(
        uint256,
        address,
        bytes32,
        bytes memory
    ) external view returns (uint256) {
        return returnValue;
    }
}
