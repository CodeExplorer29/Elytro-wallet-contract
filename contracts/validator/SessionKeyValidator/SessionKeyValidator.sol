// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator} from "@elytro-wallet-core/contracts/interface/IValidator.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import {UserOperationLib} from "@account-abstraction/contracts/core/UserOperationLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Errors} from "../../libraries/Errors.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IStandardExecutor, Execution} from "@elytro-wallet-core/contracts/interface/IStandardExecutor.sol";
import {StorageLib, StoragePointer} from "../libraries/StorageLib.sol";

/**
 * @title SessionKeyValidator
 * @dev A contract that implements the IValidator interface for validating user operations and signatures.
 */
contract SessionKeyValidator is IValidator {
    using UserOperationLib for PackedUserOperation;

    // Magic value indicating a valid signature for ERC-1271 contracts
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // Constants indicating different invalid states
    bytes4 internal constant INVALID_ID = 0xffffffff;
    bytes4 internal constant INVALID_TIME_RANGE = 0xfffffffe;
    /*
    The plugin stores permissions in an id-namespaced layout.
    It first maps (wallet, sessionKey) → sessionKeyId. All rule data is stored under (wallet, sessionKeyId, …).
    To revoke or “reset” a session key, the plugin assigns a new sessionKeyId to the same session key address. This makes all previous
    session key info, session key token info, session key function info storage unreachable without requiring on-chain cleanup of old nested storage.
    */
    type SessionKeyId is bytes32;

    struct SessionKeyInfo {
        address target; // 0x01 target / 0x04 allowed validateSignature caller
        // Unix timestamp until which the session key is valid.
        uint48 validUntil;
        bool isActive;
        /*
        - key type 0x1: approved Target -> approvedTargetAddress
        - key type 0x2: approved Target+Method -> approvedTargetAddress, method(bytes4)
        - key type 0x3: erc20Limit spend limit
        - key type 0x4: approved validateSignature Target
        */
        uint8 keyType;
        // Total lifetime gas budget allowed for this session key
        uint32 gasLimit;
        // Cumulative gas budget already consumed by this session key
        uint32 gasUsed;
    }

    struct SessionKeyTokenInfo {
        uint256 limitAmount;
        uint256 limitUsed;
    }

    struct SessionKeyFunctionInfo {
        bytes4 selector;
    }

    bytes4 internal constant SESSION_KEY_ID_PREFIX = bytes4(keccak256("SessionKeyId"));
    bytes4 internal constant SESSION_KEY_INFO_PREFIX = bytes4(keccak256("SessionKeyInfo"));
    bytes4 internal constant SESSION_KEY_TOKEN_INFO_PREFIX = bytes4(keccak256("SessionKeyTokenInfo"));
    bytes4 internal constant SESSION_KEY_FUNCTION_INFO_PREFIX = bytes4(keccak256("SessionKeyFunctionInfo"));
    bytes4 internal constant SESSION_KEY_LIST_PREFIX = bytes4(keccak256("SessionKeyList"));
    bytes4 internal constant SESSION_KEY_LIST_INDEX_PREFIX = bytes4(keccak256("SessionKeyListIndex"));

    function _sessionKeyId(address associated, address sessionKey) internal view returns (SessionKeyId sessionKeyId) {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_ID_PREFIX));
        bytes memory associatedStorageKey = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        StoragePointer ptr =
            StorageLib.associatedStorageLookup(associatedStorageKey, bytes32(uint256(uint160(sessionKey))));
        assembly ("memory-safe") {
            sessionKeyId := sload(ptr)
        }
    }

    function _loadSessionKey(address associated, address sessionKey) internal view returns (SessionKeyId keyId) {
        SessionKeyId id = _sessionKeyId(associated, sessionKey);
        if (SessionKeyId.unwrap(id) == bytes32(0)) {
            revert("session key not found");
        }
        return id;
    }

    function _autoIncrementSessionKeyId(address associated, address sessionKey) internal {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_ID_PREFIX));
        bytes memory associatedStorageKey = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        StoragePointer ptr =
            StorageLib.associatedStorageLookup(associatedStorageKey, bytes32(uint256(uint160(sessionKey))));
        SessionKeyId currentSessionKeyId;
        assembly ("memory-safe") {
            currentSessionKeyId := sload(ptr)
        }

        uint256 newId = uint256(SessionKeyId.unwrap(currentSessionKeyId)) + 1;
        assembly ("memory-safe") {
            sstore(ptr, newId)
        }
    }

    function _sessionKeyInfo(address associated, address sessionKey)
        internal
        pure
        returns (SessionKeyInfo storage sessionKeyInfo)
    {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_INFO_PREFIX));
        bytes memory key = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        return _toSessionKeyData(StorageLib.associatedStorageLookup(key, bytes32(uint256(uint160(sessionKey)))));
    }

    function _sessionKeyTokenInfo(address associated, address sessionKey, address contractAddress)
        internal
        view
        returns (SessionKeyTokenInfo storage sessionKeyTokenInfo)
    {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_TOKEN_INFO_PREFIX));
        bytes memory associatedStorageKey = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 2);

        SessionKeyId sessionKeyId = _sessionKeyId(associated, sessionKey);

        bytes32 contractDataKey1 = SessionKeyId.unwrap(sessionKeyId);
        bytes32 contractDataKey2 = bytes32(uint256(uint160(contractAddress)));
        return _toSessionKeyTokenData(
            StorageLib.associatedStorageLookup(associatedStorageKey, contractDataKey1, contractDataKey2)
        );
    }

    function _sessionKeyFunctionInfo(address associated, address sessionKey, address contractAddress)
        internal
        view
        returns (SessionKeyFunctionInfo storage sessionKeyFunctionInfo)
    {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_FUNCTION_INFO_PREFIX));
        bytes memory associatedStorageKey = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 2);
        SessionKeyId sessionKeyId = _sessionKeyId(associated, sessionKey);

        bytes32 contractDataKey1 = SessionKeyId.unwrap(sessionKeyId);
        bytes32 contractDataKey2 = bytes32(uint256(uint160(contractAddress)));
        return _toSessionKeyFunctionData(
            StorageLib.associatedStorageLookup(associatedStorageKey, contractDataKey1, contractDataKey2)
        );
    }

    function _toSessionKeyData(StoragePointer ptr) internal pure returns (SessionKeyInfo storage sessionKeyInfo) {
        assembly ("memory-safe") {
            sessionKeyInfo.slot := ptr
        }
    }

    function _toSessionKeyFunctionData(StoragePointer ptr)
        internal
        pure
        returns (SessionKeyFunctionInfo storage sessionKeyFunctionInfo)
    {
        assembly ("memory-safe") {
            sessionKeyFunctionInfo.slot := ptr
        }
    }

    function _toSessionKeyTokenData(StoragePointer ptr)
        internal
        pure
        returns (SessionKeyTokenInfo storage sessionKeyTokenInfo)
    {
        assembly ("memory-safe") {
            sessionKeyTokenInfo.slot := ptr
        }
    }

    function _sessionKeyListEntryPtr(address associated, uint256 slotIndex) internal pure returns (StoragePointer ptr) {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_LIST_PREFIX));
        bytes memory key = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        // slot 0 stores the length, subsequent slots store session key addresses
        return StorageLib.associatedStorageLookup(key, bytes32(slotIndex));
    }

    function _sessionKeyIndexPtr(address associated, address sessionKey) internal pure returns (StoragePointer ptr) {
        uint256 prefixAndBatchIndex = uint256(bytes32(SESSION_KEY_LIST_INDEX_PREFIX));
        bytes memory key = StorageLib.allocateAssociatedStorageKey(associated, prefixAndBatchIndex, 1);
        return StorageLib.associatedStorageLookup(key, bytes32(uint256(uint160(sessionKey))));
    }

    function _sessionKeyListLength(address associated) internal view returns (uint256 length) {
        StoragePointer lenPtr = _sessionKeyListEntryPtr(associated, 0);
        assembly ("memory-safe") {
            length := sload(lenPtr)
        }
    }

    function _sessionKeyAt(address associated, uint256 index) internal view returns (address sessionKey) {
        StoragePointer entryPtr = _sessionKeyListEntryPtr(associated, index + 1);
        assembly ("memory-safe") {
            sessionKey := and(sload(entryPtr), 0xffffffffffffffffffffffffffffffffffffffff)
        }
    }

    function _trackSessionKey(address associated, address sessionKey) internal {
        StoragePointer indexPtr = _sessionKeyIndexPtr(associated, sessionKey);
        uint256 idxPlusOne;
        assembly ("memory-safe") {
            idxPlusOne := sload(indexPtr)
        }
        if (idxPlusOne != 0) {
            return;
        }

        uint256 length = _sessionKeyListLength(associated);
        uint256 newLength = length + 1;
        StoragePointer lenPtr = _sessionKeyListEntryPtr(associated, 0);
        StoragePointer entryPtr = _sessionKeyListEntryPtr(associated, newLength);
        uint256 encodedKey = uint256(uint160(sessionKey));
        assembly ("memory-safe") {
            sstore(entryPtr, encodedKey)
            sstore(lenPtr, newLength)
            sstore(indexPtr, newLength)
        }
    }

    function setSessionKey(address sessionKey, SessionKeyInfo memory sessionKeyInfo) public {
        SessionKeyInfo storage storedInfo = _sessionKeyInfo(msg.sender, sessionKey);
        storedInfo.target = sessionKeyInfo.target;
        storedInfo.validUntil = sessionKeyInfo.validUntil;
        storedInfo.isActive = sessionKeyInfo.isActive;
        storedInfo.keyType = sessionKeyInfo.keyType;
        storedInfo.gasLimit = sessionKeyInfo.gasLimit;
        storedInfo.gasUsed = sessionKeyInfo.gasUsed;
        _trackSessionKey(msg.sender, sessionKey);
    }

    function _setSessionKeyTokenInfo(
        address associated,
        address sessionKey,
        address token,
        SessionKeyTokenInfo memory tokenInfo
    ) internal {
        SessionKeyTokenInfo storage storedInfo = _sessionKeyTokenInfo(associated, sessionKey, token);
        storedInfo.limitAmount = tokenInfo.limitAmount;
        storedInfo.limitUsed = tokenInfo.limitUsed;
    }

    function _setSessionKeyFunctionInfo(address associated, address sessionKey, address target, bytes4 selector)
        internal
    {
        SessionKeyFunctionInfo storage functionInfo = _sessionKeyFunctionInfo(associated, sessionKey, target);
        functionInfo.selector = selector;
    }

    function Init(bytes calldata args) external override {
        (address sessionKey, SessionKeyInfo memory sessionKeyInfo, bytes memory extraData) =
            abi.decode(args, (address, SessionKeyInfo, bytes));

        if (sessionKey == address(0) || sessionKeyInfo.target == address(0)) {
            revert Errors.INVALID_ADDRESS();
        }

        setSessionKey(sessionKey, sessionKeyInfo);

        if (sessionKeyInfo.keyType == 0x02) {
            if (extraData.length == 0) {
                revert Errors.INVALID_DATA();
            }
            bytes4 selector = abi.decode(extraData, (bytes4));
            _setSessionKeyFunctionInfo(msg.sender, sessionKey, sessionKeyInfo.target, selector);
        } else if (sessionKeyInfo.keyType == 0x03) {
            if (extraData.length == 0) {
                revert Errors.INVALID_DATA();
            }
            (address[] memory tokens, SessionKeyTokenInfo[] memory tokenInfos) =
                abi.decode(extraData, (address[], SessionKeyTokenInfo[]));
            uint256 tokenCount = tokens.length;
            if (tokenCount == 0 || tokenCount != tokenInfos.length) {
                revert Errors.INVALID_DATA();
            }
            for (uint256 i = 0; i < tokenCount; i++) {
                if (tokens[i] == address(0)) {
                    revert Errors.INVALID_ADDRESS();
                }
                _setSessionKeyTokenInfo(msg.sender, sessionKey, tokens[i], tokenInfos[i]);
            }
        } else if (extraData.length != 0) {
            revert Errors.INVALID_DATA();
        }
    }

    function DeInit() external override {
        address wallet = msg.sender;
        uint256 length = _sessionKeyListLength(wallet);
        if (length == 0) {
            return;
        }
        for (uint256 i = 0; i < length; i++) {
            address sessionKey = _sessionKeyAt(wallet, i);
            if (sessionKey == address(0)) {
                continue;
            }
            _autoIncrementSessionKeyId(wallet, sessionKey);

            SessionKeyInfo storage info = _sessionKeyInfo(wallet, sessionKey);
            info.target = address(0);
            info.validUntil = 0;
            info.isActive = false;
            info.keyType = 0;
            info.gasLimit = 0;
            info.gasUsed = 0;

            StoragePointer indexPtr = _sessionKeyIndexPtr(wallet, sessionKey);
            StoragePointer entryPtr = _sessionKeyListEntryPtr(wallet, i + 1);
            assembly ("memory-safe") {
                sstore(indexPtr, 0)
                sstore(entryPtr, 0)
            }
        }
        StoragePointer lenPtr = _sessionKeyListEntryPtr(wallet, 0);
        assembly ("memory-safe") {
            sstore(lenPtr, 0)
        }
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata validatorSignature)
        external
        override
        returns (uint256 validationData)
    {
        (address sessionKey, bool recovered) = _recoverSessionKey(userOpHash, validatorSignature);
        if (!recovered) {
            return SIG_VALIDATION_FAILED;
        }
        address walletAddress = userOp.sender;
        SessionKeyInfo storage sessionKeyInfo = _sessionKeyInfo(walletAddress, sessionKey);

        if (!_isSessionKeyActive(sessionKeyInfo)) {
            return SIG_VALIDATION_FAILED;
        }

        if (sessionKeyInfo.keyType == 0x04 || sessionKeyInfo.keyType == 0x00) {
            return SIG_VALIDATION_FAILED;
        }

        if (!_isWithinTimeRange(sessionKeyInfo.validUntil)) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 declaredGas = userOp.unpackCallGasLimit();
        if (declaredGas > type(uint32).max) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 newGasUsed = uint256(sessionKeyInfo.gasUsed) + declaredGas;
        if (newGasUsed > type(uint32).max) {
            return SIG_VALIDATION_FAILED;
        }
        if (sessionKeyInfo.gasLimit != 0 && newGasUsed > sessionKeyInfo.gasLimit) {
            return SIG_VALIDATION_FAILED;
        }

        Execution[] memory executions;
        try this._decodeExecutions(userOp.callData) returns (Execution[] memory decoded) {
            executions = decoded;
        } catch {
            return SIG_VALIDATION_FAILED;
        }

        if (executions.length == 0) {
            return SIG_VALIDATION_FAILED;
        }

        (bool rulesOk, uint256 erc20Spend) = _validateExecutions(sessionKeyInfo, walletAddress, sessionKey, executions);
        if (!rulesOk) {
            return SIG_VALIDATION_FAILED;
        }

        if (sessionKeyInfo.keyType == 0x03 && erc20Spend > 0) {
            SessionKeyTokenInfo storage tokenInfo =
                _sessionKeyTokenInfo(walletAddress, sessionKey, sessionKeyInfo.target);
            uint256 newTokenSpend = tokenInfo.limitUsed + erc20Spend;
            if (newTokenSpend > tokenInfo.limitAmount) {
                return SIG_VALIDATION_FAILED;
            }
            tokenInfo.limitUsed = newTokenSpend;
        }

        sessionKeyInfo.gasUsed = uint32(newGasUsed);

        ValidationData memory data =
            ValidationData({aggregator: address(0), validAfter: 0, validUntil: sessionKeyInfo.validUntil});
        return _packValidationData(data);
    }

    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        return interfaceId == type(IValidator).interfaceId;
    }

    function validateSignature(address sender, bytes32 rawHash, bytes calldata validatorSignature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        (address sessionKey, bool recovered) = _recoverSessionKey(rawHash, validatorSignature);
        if (!recovered) {
            return INVALID_ID;
        }

        SessionKeyInfo storage sessionKeyInfo = _sessionKeyInfo(sender, sessionKey);
        if (!_isSessionKeyActive(sessionKeyInfo)) {
            return INVALID_ID;
        }

        if (sessionKeyInfo.keyType != 0x04 || sessionKeyInfo.target != msg.sender) {
            return INVALID_ID;
        }

        if (!_isWithinTimeRange(sessionKeyInfo.validUntil)) {
            return INVALID_TIME_RANGE;
        }

        return MAGICVALUE;
    }

    function _recoverSessionKey(bytes32 digest, bytes calldata validatorSignature)
        internal
        pure
        returns (address sessionKey, bool success)
    {
        if (validatorSignature.length < 65) {
            return (address(0), false);
        }
        (address recoveredAddr, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, validatorSignature[0:65]);
        if (error != ECDSA.RecoverError.NoError) {
            return (address(0), false);
        }
        return (recoveredAddr, true);
    }

    function _isSessionKeyActive(SessionKeyInfo storage sessionKeyInfo) internal view returns (bool) {
        return sessionKeyInfo.isActive;
    }

    function _isWithinTimeRange(uint48 validUntil) internal view returns (bool) {
        if (validUntil == 0) {
            return true;
        }
        return block.timestamp <= validUntil;
    }

    function _decodeExecutions(bytes calldata callData) external pure returns (Execution[] memory executions) {
        if (callData.length < 4) {
            revert Errors.INVALID_DATA();
        }

        bytes4 selector;
        assembly {
            selector := calldataload(callData.offset)
        }

        if (selector == IStandardExecutor.execute.selector) {
            (address target, uint256 value, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            executions = new Execution[](1);
            executions[0] = Execution({target: target, value: value, data: data});
        } else if (selector == IStandardExecutor.executeBatch.selector) {
            executions = abi.decode(callData[4:], (Execution[]));
        } else {
            revert Errors.INVALID_DATA();
        }
    }

    function _validateExecutions(
        SessionKeyInfo storage sessionKeyInfo,
        address wallet,
        address sessionKey,
        Execution[] memory executions
    ) internal view returns (bool isValid, uint256 tokenSpend) {
        if (sessionKeyInfo.target == address(0)) {
            return (false, 0);
        }

        if (sessionKeyInfo.keyType == 0x01) {
            for (uint256 i = 0; i < executions.length; i++) {
                if (executions[i].target != sessionKeyInfo.target) {
                    return (false, 0);
                }
            }
            return (true, 0);
        }

        if (sessionKeyInfo.keyType == 0x02) {
            SessionKeyFunctionInfo storage functionInfo =
                _sessionKeyFunctionInfo(wallet, sessionKey, sessionKeyInfo.target);
            if (functionInfo.selector == bytes4(0)) {
                return (false, 0);
            }
            for (uint256 i = 0; i < executions.length; i++) {
                if (executions[i].target != sessionKeyInfo.target) {
                    return (false, 0);
                }
                if (executions[i].data.length < 4 || bytes4(executions[i].data) != functionInfo.selector) {
                    return (false, 0);
                }
            }
            return (true, 0);
        }

        if (sessionKeyInfo.keyType == 0x03) {
            for (uint256 i = 0; i < executions.length; i++) {
                Execution memory execution = executions[i];
                if (execution.target != sessionKeyInfo.target || execution.value != 0) {
                    return (false, 0);
                }
                if (execution.data.length < 4) {
                    return (false, 0);
                }

                bytes4 selector = bytes4(execution.data);
                if (selector == IERC20.transfer.selector) {
                    if (execution.data.length < 68) {
                        return (false, 0);
                    }
                    uint256 amount = _decodeTransferAmount(execution.data);
                    tokenSpend += amount;
                } else if (selector == IERC20.transferFrom.selector) {
                    if (execution.data.length < 100) {
                        return (false, 0);
                    }
                    (address from, uint256 amount) = _decodeTransferFrom(execution.data);
                    if (from != wallet) {
                        return (false, 0);
                    }
                    tokenSpend += amount;
                } else {
                    return (false, 0);
                }
            }
            return (true, tokenSpend);
        }

        return (false, 0);
    }

    function _decodeTransferAmount(bytes memory callData) internal pure returns (uint256 amount) {
        assembly {
            amount := mload(add(callData, 68))
        }
    }

    function _decodeTransferFrom(bytes memory callData) internal pure returns (address from, uint256 amount) {
        assembly {
            from := shr(96, mload(add(callData, 36)))
            amount := mload(add(callData, 100))
        }
    }
}
