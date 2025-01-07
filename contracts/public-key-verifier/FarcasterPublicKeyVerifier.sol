// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "./IFarcasterPublicKeyVerifier.sol";
import "./IKeyRegistry.sol";

contract FarcasterPublicKeyVerifier is
    IFarcasterPublicKeyVerifier,
    AccessControl,
    Multicall
{
    /// @notice Role identifier for operator role (OptimismGovernor)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Role identifier for security role (Security Council)
    bytes32 public constant SECURITY_ROLE = keccak256("SECURITY_ROLE");

    /// @notice The Key Registry contract.
    IKeyRegistry public immutable keyRegistry;

    /// @notice The external Key Registry mapping.
    mapping(uint256 => mapping(bytes32 => bool)) public keyExternal;

    /// @notice Event emitted when a key is added.
    event AddKey(uint256 indexed fid, bytes32 indexed publicKey);

    /// @notice Event emitted when a key is removed.
    event RemoveKey(uint256 indexed fid, bytes32 indexed publicKey);

    /// @notice Event emitted when an operator is blacklisted.
    event BlacklistOperator(address indexed operator);

    /// @notice Error emitted when an operator is blacklisted.
    error BlacklistedOperator();

    /**
     * @dev Constructor to set the Key Registry contract.
     * @param registry The address of the Key Registry contract.
     */
    constructor(IKeyRegistry registry, address admin) {
        keyRegistry = registry;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
    }

    /**
     * @notice Verifies if the given public key is valid for the specified Farcaster ID (FID).
     * @param fid The Farcaster ID (FID) of the user.
     * @param publicKey The public key to be verified.
     * @return bool indicating whether the public key is valid.
     */
    function verifyPublicKey(
        uint256 fid,
        bytes32 publicKey
    ) external view returns (bool) {
        if (keyExternal[fid][publicKey]) {
            return true;
        }

        IKeyRegistry.KeyData memory data = keyRegistry.keyDataOf(
            fid,
            abi.encodePacked(publicKey)
        );
        return (data.state == IKeyRegistry.KeyState.ADDED && data.keyType == 1);
    }

    /**
     * @notice Adds a public key to the external mapping.
     * @param fid The Farcaster ID (FID) of the user.
     * @param publicKey The public key to be added.
     */
    function addKey(
        uint256 fid,
        bytes32 publicKey
    ) external onlyRole(OPERATOR_ROLE) {
        keyExternal[fid][publicKey] = true;
        emit AddKey(fid, publicKey);
    }

    /**
     * @notice Remove a public key from the external mapping.
     * @param fid The Farcaster ID (FID) of the user.
     * @param publicKey The public key to be removed.
     */
    function removeKey(
        uint256 fid,
        bytes32 publicKey
    ) external onlyRole(OPERATOR_ROLE) {
        keyExternal[fid][publicKey] = false;
        emit RemoveKey(fid, publicKey);
    }

    /**
     * @notice Blacklists an operator by revoking their OPERATOR_ROLE.
     * @dev Can only be called by accounts with SECURITY_ROLE.
     * @param operator The address of the operator to blacklist.
     */
    function blacklistOperator(
        address operator
    ) external onlyRole(SECURITY_ROLE) {
        _revokeRole(OPERATOR_ROLE, operator);
        emit BlacklistOperator(operator);
    }
}
