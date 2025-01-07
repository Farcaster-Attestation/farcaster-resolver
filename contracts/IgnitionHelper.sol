// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/**
 * @title IgnitionHelper
 * @notice Helper contract for deploying and initializing EAS and SchemaRegistry contracts
 * @dev This contract imports artifacts from EAS and SchemaRegistry for use in ignition deployment scripts
 */

// This module import artifact of EAS and SchemaRegistry for using in the ignition script
import "@ethereum-attestation-service/eas-contracts/contracts/EAS.sol";
import "@ethereum-attestation-service/eas-contracts/contracts/SchemaRegistry.sol";
