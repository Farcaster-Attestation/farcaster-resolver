// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {IL2ToL2CrossDomainMessenger} from "./IL2ToL2CrossDomainMessenger.sol";

import {IFarcasterResolver} from "../IFarcasterResolver.sol";

/**
 * @title FarcasterResolverInterop
 * @notice A standalone contract that:
 *         1) On a "source" chain (e.g. chain #10), calls a real FarcasterResolver for EAS-based operations.
 *         2) On other chains, it stores attestation info in local mappings.
 *         3) Supports cross-chain calls to "attest" or "revoke" on another chain.
 */
contract FarcasterResolverInterop is IFarcasterResolver {
    using EnumerableMap for EnumerableMap.UintToUintMap;
    using EnumerableMap for EnumerableMap.UintToAddressMap;

    // ------------------------------------------------------------------------
    // ERRORS
    // ------------------------------------------------------------------------

    /**
     * @dev Thrown when a function is called by an address other than the L2ToL2CrossDomainMessenger.
     */
    error CallerNotL2ToL2CrossDomainMessenger();

    /**
     * @dev Thrown when the cross-domain sender is not this contract's address on another chain.
     */
    error InvalidCrossDomainSender();

    /**
     * @dev Thrown if we try to cross-chain message to the same chain.
     */
    error InvalidDestination();

    /**
     * @dev Thrown if we try to call write functions on the source chain.
     */
    error NotAllowedOnSourceChain();

    /**
     * @dev Thrown if we try to call cross-chain functions on non-source chain.
     */
    error NotSourceChain();

    // ------------------------------------------------------------------------
    // CONFIG
    // ------------------------------------------------------------------------

    /// @dev True if this contract is running on the source chain.
    bool public immutable isSourceChain;

    /// @dev The address of the FarcasterResolver on the source chain (only used if isSourceChain == true).
    IFarcasterResolver public immutable sourceResolver;

    // ------------------------------------------------------------------------
    // LOCAL STORAGE (only used if isSourceChain == false)
    // ------------------------------------------------------------------------

    // Mapping: wallet => (key => fid)
    mapping(address => EnumerableMap.UintToUintMap) internal localWalletAttestations;

    // Mapping: fid => (key => wallet)
    mapping(uint256 => EnumerableMap.UintToAddressMap) internal localFidAttestations;

    // ------------------------------------------------------------------------
    // MESSENGER
    // ------------------------------------------------------------------------

    IL2ToL2CrossDomainMessenger internal messenger =
        IL2ToL2CrossDomainMessenger(0x4200000000000000000000000000000000000023);

    // ------------------------------------------------------------------------
    // CONSTRUCTOR
    // ------------------------------------------------------------------------

    /**
     * @param _sourceResolverAddr The address of the real FarcasterResolver on chain #10.
     *                            If the current chain is chain #10, we'll call it;
     *                            otherwise it's unused (can be set to zero).
     */
    constructor(address _sourceResolverAddr, uint256 _sourceChainId) {
        isSourceChain = (block.chainid == _sourceChainId);
        sourceResolver = IFarcasterResolver(_sourceResolverAddr);
    }

    // ------------------------------------------------------------------------
    // CROSS-CHAIN
    // ------------------------------------------------------------------------

    modifier onlyCrossDomainCallback() {
        if (msg.sender != address(messenger)) {
            revert CallerNotL2ToL2CrossDomainMessenger();
        }
        if (messenger.crossDomainMessageSender() != address(this)) {
            revert InvalidCrossDomainSender();
        }
        _;
    }

    event CrossChainSyncInitiated(
        uint256 indexed toChainId,
        address indexed recipient,
        uint256 indexed fid,
        bool isRevoke
    );

    /**
     * @notice Cross-chain "attest" or "revoke" from current chain to `_toChainId`.
     *         On the receiving chain, `receiveSync(...)` will be called
     *         according to the verification status on the source chain.
     */
    function crossChainSync(
        uint256 _toChainId,
        address _recipient,
        uint256 _fid
    ) external {
        if (!isSourceChain) revert NotSourceChain();
        if (_toChainId == block.chainid) revert InvalidDestination();

        bool isRevoke = sourceResolver.isVerified(_fid, _recipient);

        // Encode the function call
        bytes memory message = abi.encodeCall(
            this.receiveSync,
            (_recipient, _fid, isRevoke)
        );

        // Send
        messenger.sendMessage(_toChainId, address(this), message);

        emit CrossChainSyncInitiated(
            _toChainId,
            _recipient,
            _fid,
            isRevoke
        );
    }

    /**
     * @notice Receiving side of the cross-chain "attest" or "revoke".
     *         Only callable via cross-domain messenger, from this same contract on origin chain.
     */
    function receiveSync(
        address _recipient,
        uint256 _fid,
        bool _isRevoke
    ) external onlyCrossDomainCallback {
        if (isSourceChain) {
            revert NotAllowedOnSourceChain();
        } else {
            // On other chains, store locally
            if (_isRevoke) {
                _localRevoke(
                    _recipient,
                    _fid
                );
            } else {
                _localAttest(
                    _recipient,
                    _fid
                );
            }
        }
    }

    // ------------------------------------------------------------------------
    // LOCAL STORAGE METHODS (used only if !isSourceChain)
    // ------------------------------------------------------------------------

    function _localAttest(
        address _recipient,
        uint256 _fid
    ) internal returns (bytes32) {
        bytes32 key = computeKey(_fid, _recipient);

        // Store
        localWalletAttestations[_recipient].set(uint256(key), _fid);
        localFidAttestations[_fid].set(uint256(key), _recipient);

        emit VerificationAttested(
            _fid,
            _recipient,
            0,
            bytes32(0),
            ""
        );
        return key;
    }

    function _localRevoke(
        address _recipient,
        uint256 _fid
    ) internal returns (bool) {
        bytes32 key = computeKey(_fid, _recipient);

        // Remove from local store
        localWalletAttestations[_recipient].remove(uint256(key));
        localFidAttestations[_fid].remove(uint256(key));

        emit VerificationRevoked(
            _fid,
            _recipient,
            0,
            bytes32(0),
            ""
        );
        return true;
    }

    // ------------------------------------------------------------------------
    // PUBLIC/EXTERNAL VIEW FUNCTIONS
    // ------------------------------------------------------------------------

    function computeKey(uint256 _fid, address _verifyAddr) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_fid, _verifyAddr));
    }

    /**
     * @notice Return the attestation UID for a given fid/wallet, either from the real
     *         FarcasterResolver (if isSourceChain) or from local storage.
     */
    function getAttestationUid(uint256 fid, address wallet) public view returns (bytes32) {
        if (isSourceChain) {
            return sourceResolver.getAttestationUid(fid, wallet);
        } else {
            bytes32 key = computeKey(fid, wallet);
            return key;
        }
    }

    function isVerified(uint256 fid, address wallet) public view returns (bool) {
        return getAttestationUid(fid, wallet) != bytes32(0);
    }

    // -- walletAttestations

    function walletAttestationsLength(address wallet) public view returns (uint256) {
        if (isSourceChain) {
            return sourceResolver.walletAttestationsLength(wallet);
        } else {
            return localWalletAttestations[wallet].length();
        }
    }

    function getWalletAttestations(
        address wallet
    ) external view returns (uint256[] memory fids, bytes32[] memory uids) {
        return getWalletAttestations(wallet, 0, walletAttestationsLength(wallet));
    }

    function getWalletAttestations(
        address wallet,
        uint256 start,
        uint256 len
    ) public view returns (uint256[] memory fids, bytes32[] memory uids) {
        if (isSourceChain) {
            return sourceResolver.getWalletAttestations(wallet, start, len);
        } else {
            fids = new uint256[](len);
            uids = new bytes32[](len);
            for (uint256 i; i < len; ) {
                (uint256 uidVal, uint256 fidVal) = localWalletAttestations[wallet].at(start + i);
                fids[i] = fidVal;
                uids[i] = bytes32(uidVal);
                unchecked {
                    ++i;
                }
            }
        }
    }

    // -- fidAttestations

    function fidAttestationsLength(uint256 fid) public view returns (uint256) {
        if (isSourceChain) {
            return sourceResolver.fidAttestationsLength(fid);
        } else {
            return localFidAttestations[fid].length();
        }
    }

    function getFidAttestations(uint256 fid) external view returns (address[] memory wallets, bytes32[] memory uids) {
        return getFidAttestations(fid, 0, fidAttestationsLength(fid));
    }

    function getFidAttestations(
        uint256 fid,
        uint256 start,
        uint256 len
    ) public view returns (address[] memory wallets, bytes32[] memory uids) {
        if (isSourceChain) {
            return sourceResolver.getFidAttestations(fid, start, len);
        } else {
            wallets = new address[](len);
            uids = new bytes32[](len);
            for (uint256 i; i < len; ) {
                (uint256 uidVal, address walletVal) = localFidAttestations[fid].at(start + i);
                wallets[i] = walletVal;
                uids[i] = bytes32(uidVal);
                unchecked {
                    ++i;
                }
            }
        }
    }
}