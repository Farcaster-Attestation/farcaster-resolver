pragma solidity ^0.8.0;

interface IERC1271 {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param hash      Hash of the data to be signed
     * @param signature Signature byte array associated with `hash`
     */
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4 magicValue);
}

interface IFarcasterResolverInterop {
    function enableInterop(uint256 chainId) external;
}

contract MaliciousSmartWallet is IERC1271 {
    bool public isOn;

    constructor() payable {
        isOn = true;
    }

    function signatureSwitch(bool _isOn) public {
        isOn = _isOn;
    }

    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) public view returns (bytes4 magicValue) {
        if (isOn) {
            return IERC1271.isValidSignature.selector;
        } else {
            return 0xffffffff;
        }
    }

    function enableInterop(address interop, uint256 chainId) public {
        IFarcasterResolverInterop(interop).enableInterop(chainId);
    }

    fallback() external payable {}
}
