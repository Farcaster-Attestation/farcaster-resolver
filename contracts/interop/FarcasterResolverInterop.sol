// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {IL2ToL2CrossDomainMessenger} from "./IL2ToL2CrossDomainMessenger.sol";

import {IFarcasterResolver} from "../IFarcasterResolver.sol";

/**
 * @title FarcasterResolverInterop
 * @notice A contract that enables cross-chain interoperability for Farcaster wallet verifications.
 * @dev This contract serves two main purposes:
 *      1. On the source chain (e.g. OP Mainnet), it acts as a wrapper around the main FarcasterResolver,
 *         forwarding all verification queries to it.
 *      2. On other chains (e.g. Base), it maintains a local copy of verifications that can be synced
 *         from the source chain.
 *
 * The contract uses the L2ToL2CrossDomainMessenger to enable cross-chain communication between
 * different chains in the Superchain. This allows wallet verifications to be propagated from
 * the source chain to other chains.
 *
 * Key features:
 * - Maintains local storage of wallet <-> FID attestations on non-OP Mainnet chains
 * - Provides cross-chain syncing of attestations from OP Mainnet
 * - Implements the same interface as FarcasterResolver for seamless integration
 * - Uses EnumerableMap for efficient storage and retrieval of attestations
 *
 * The contract is designed to be deployed deterministically to the same address across all chains,
 * making cross-chain messaging simpler and more predictable.
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

    /// @dev Maps wallet addresses to their attestations (key => fid)
    mapping(address => EnumerableMap.UintToUintMap)
        internal localWalletAttestations;

    /// @dev Maps FIDs to their attestations (key => wallet)
    mapping(uint256 => EnumerableMap.UintToAddressMap)
        internal localFidAttestations;

    /// @dev Maps attestation keys to verification status
    mapping(bytes32 => bool) internal _isVerified;

    // ------------------------------------------------------------------------
    // MESSENGER
    // ------------------------------------------------------------------------

    /// @dev The L2ToL2CrossDomainMessenger contract used for cross-chain communication
    IL2ToL2CrossDomainMessenger internal messenger =
        IL2ToL2CrossDomainMessenger(0x4200000000000000000000000000000000000023);

    // ------------------------------------------------------------------------
    // CONSTRUCTOR
    // ------------------------------------------------------------------------

    /**
     * @param _sourceResolverAddr The address of the real FarcasterResolver on chain #10.
     *                            If the current chain is chain #10, we'll call it;
     *                            otherwise it's unused (can be set to zero).
     * @param _sourceChainId The chain ID of the source chain (e.g. 10 for OP Mainnet)
     */
    constructor(address _sourceResolverAddr, uint256 _sourceChainId) {
        isSourceChain = (block.chainid == _sourceChainId);
        sourceResolver = IFarcasterResolver(_sourceResolverAddr);
    }

    // ------------------------------------------------------------------------
    // CROSS-CHAIN
    // ------------------------------------------------------------------------

    /**
     * @dev Modifier to ensure function can only be called via the cross-domain messenger
     */
    modifier onlyCrossDomainCallback() {
        if (msg.sender != address(messenger)) {
            revert CallerNotL2ToL2CrossDomainMessenger();
        }
        if (messenger.crossDomainMessageSender() != address(this)) {
            revert InvalidCrossDomainSender();
        }
        _;
    }

    /**
     * @dev Emitted when a cross-chain sync is initiated
     * @param toChainId The destination chain ID
     * @param recipient The wallet address being synced
     * @param fid The Farcaster ID being synced
     * @param isRevoke Whether this is a revocation (true) or attestation (false)
     */
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
     * @param _toChainId The destination chain ID
     * @param _recipient The wallet address to sync
     * @param _fid The Farcaster ID to sync
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

        emit CrossChainSyncInitiated(_toChainId, _recipient, _fid, isRevoke);
    }

    /**
     * @notice Receiving side of the cross-chain "attest" or "revoke".
     *         Only callable via cross-domain messenger, from this same contract on origin chain.
     * @param _recipient The wallet address to sync
     * @param _fid The Farcaster ID to sync
     * @param _isRevoke Whether this is a revocation (true) or attestation (false)
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
                _localRevoke(_recipient, _fid);
            } else {
                _localAttest(_recipient, _fid);
            }
        }
    }

    // ------------------------------------------------------------------------
    // LOCAL STORAGE METHODS (used only if !isSourceChain)
    // ------------------------------------------------------------------------

    /**
     * @notice Creates a local attestation between a wallet and FID
     * @param _recipient The wallet address
     * @param _fid The Farcaster ID
     * @return The attestation key
     */
    function _localAttest(
        address _recipient,
        uint256 _fid
    ) internal returns (bytes32) {
        bytes32 key = computeKey(_fid, _recipient);

        // Store
        localWalletAttestations[_recipient].set(uint256(key), _fid);
        localFidAttestations[_fid].set(uint256(key), _recipient);
        _isVerified[key] = true;

        emit VerificationAttested(_fid, _recipient, 0, bytes32(0), "");
        return key;
    }

    /**
     * @notice Revokes a local attestation between a wallet and FID
     * @param _recipient The wallet address
     * @param _fid The Farcaster ID
     * @return True if successful
     */
    function _localRevoke(
        address _recipient,
        uint256 _fid
    ) internal returns (bool) {
        bytes32 key = computeKey(_fid, _recipient);

        // Remove from local store
        localWalletAttestations[_recipient].remove(uint256(key));
        localFidAttestations[_fid].remove(uint256(key));
        _isVerified[key] = false;

        emit VerificationRevoked(_fid, _recipient, 0, bytes32(0), "");
        return true;
    }

    // ------------------------------------------------------------------------
    // PUBLIC/EXTERNAL VIEW FUNCTIONS
    // ------------------------------------------------------------------------

    /**
     * @notice Computes the unique key for a FID/wallet pair
     * @param _fid The Farcaster ID
     * @param _verifyAddr The wallet address
     * @return The computed key
     */
    function computeKey(
        uint256 _fid,
        address _verifyAddr
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(_fid, _verifyAddr));
    }

    /**
     * @notice Return the attestation UID for a given fid/wallet, either from the real
     *         FarcasterResolver (if isSourceChain) or from local storage.
     * @param fid The Farcaster ID
     * @param wallet The wallet address
     * @return The attestation UID (or bytes32(0) if not verified)
     */
    function getAttestationUid(
        uint256 fid,
        address wallet
    ) public view returns (bytes32) {
        if (isSourceChain) {
            return sourceResolver.getAttestationUid(fid, wallet);
        } else {
            bytes32 key = computeKey(fid, wallet);
            if (!_isVerified[key]) return bytes32(0);
            return key;
        }
    }

    /**
     * @notice Checks if a wallet is verified for a given FID
     * @param fid The Farcaster ID
     * @param wallet The wallet address
     * @return True if verified
     */
    function isVerified(
        uint256 fid,
        address wallet
    ) public view returns (bool) {
        return getAttestationUid(fid, wallet) != bytes32(0);
    }

    // -- walletAttestations

    /**
     * @notice Returns the number of attestations for a wallet
     * @param wallet The wallet address
     * @return The number of attestations
     */
    function walletAttestationsLength(
        address wallet
    ) public view returns (uint256) {
        if (isSourceChain) {
            return sourceResolver.walletAttestationsLength(wallet);
        } else {
            return localWalletAttestations[wallet].length();
        }
    }

    /**
     * @notice Returns all attestations for a wallet
     * @param wallet The wallet address
     * @return fids The Farcaster IDs
     * @return uids The attestation UIDs
     */
    function getWalletAttestations(
        address wallet
    ) external view returns (uint256[] memory fids, bytes32[] memory uids) {
        return
            getWalletAttestations(wallet, 0, walletAttestationsLength(wallet));
    }

    /**
     * @notice Returns a subset of attestations for a wallet
     * @param wallet The wallet address
     * @param start The starting index
     * @param len The number of attestations to return
     * @return fids The Farcaster IDs
     * @return uids The attestation UIDs
     */
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
                (uint256 uidVal, uint256 fidVal) = localWalletAttestations[
                    wallet
                ].at(start + i);
                fids[i] = fidVal;
                uids[i] = bytes32(uidVal);
                unchecked {
                    ++i;
                }
            }
        }
    }

    // -- fidAttestations

    /**
     * @notice Returns the number of attestations for a FID
     * @param fid The Farcaster ID
     * @return The number of attestations
     */
    function fidAttestationsLength(uint256 fid) public view returns (uint256) {
        if (isSourceChain) {
            return sourceResolver.fidAttestationsLength(fid);
        } else {
            return localFidAttestations[fid].length();
        }
    }

    /**
     * @notice Returns all attestations for a FID
     * @param fid The Farcaster ID
     * @return wallets The wallet addresses
     * @return uids The attestation UIDs
     */
    function getFidAttestations(
        uint256 fid
    ) external view returns (address[] memory wallets, bytes32[] memory uids) {
        return getFidAttestations(fid, 0, fidAttestationsLength(fid));
    }

    /**
     * @notice Returns a subset of attestations for a FID
     * @param fid The Farcaster ID
     * @param start The starting index
     * @param len The number of attestations to return
     * @return wallets The wallet addresses
     * @return uids The attestation UIDs
     */
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
                (uint256 uidVal, address walletVal) = localFidAttestations[fid]
                    .at(start + i);
                wallets[i] = walletVal;
                uids[i] = bytes32(uidVal);
                unchecked {
                    ++i;
                }
            }
        }
    }
}
