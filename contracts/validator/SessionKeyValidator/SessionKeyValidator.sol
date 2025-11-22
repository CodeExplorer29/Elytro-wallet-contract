// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IValidator} from "@elytro-wallet-core/contracts/interface/IValidator.sol";
import {PackedUserOpWithValidTimeRange} from "../interfaces/PackedUserOpWithValidTimeRange.sol";
import {IOwnable} from "@elytro-wallet-core/contracts/interface/IOwnable.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@account-abstraction/contracts/core/Helpers.sol";
import "../libraries/ValidatorSigDecoder.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Errors} from "../../libraries/Errors.sol";
import {TypeConversion} from "../../libraries/TypeConversion.sol";
import {WebAuthn} from "../../libraries/WebAuthn.sol";
import {IEntryPoint_v08} from "../interfaces/IEntryPoint_v08.sol";
import {UserOpWithValidTimeRangeLib} from "../libraries/UserOpWithValidTimeRangeLib.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IStandardExecutor, Execution} from "@elytro-wallet-core/contracts/interface/IStandardExecutor.sol";

/**
 * @title SessionKeyValidator
 * @dev A contract that implements the IValidator interface for validating user operations and signatures.
 */
contract SessionKeyValidator is IValidator {
    using MessageHashUtils for bytes32;
    using TypeConversion for address;
    using UserOpWithValidTimeRangeLib for PackedUserOpWithValidTimeRange;

    event SessionKeySeted(address indexed wallet, address indexed sessionKey, uint32 validUntil, bytes32 merkleRoot);

    // Magic value indicating a valid signature for ERC-1271 contracts
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // Constants indicating different invalid states
    bytes4 internal constant INVALID_ID = 0xffffffff;
    bytes4 internal constant INVALID_TIME_RANGE = 0xfffffffe;

    // EntryPoint contract address
    address public immutable entryPoint;
    bytes32 private immutable _entryPointV08DomainSeparatorV4;

    // session key

    struct SessionKeyInfo {
        address sessionKey;
        uint48 validUntil;
        /*
            merkle tree structure for session management
                - leaf node type 0x1: approved Target
                    keccak256(bytes32(abi.encodePacked(0x01, approvedTargetAddress(bytes20))))
                - leaf node type 0x2: approved Target+Method
                    keccak256(bytes32(abi.encodePacked(0x02, approvedTargetAddress(bytes20), method(bytes4)))
                - #TODO leaf node type 0x3: erc20Limit
                - leaf node type 0x4: approved validateSignature Target
                    keccak256(bytes32(abi.encodePacked(0x04, approvedTargetAddress(bytes20))))
        */
        bytes32 merkleRoot;
    }

    // key: walletAddress, value: SessionKeyInfo. [Associated storage]
    mapping(address => SessionKeyInfo) public sessionKeys;

    constructor(address _entryPoint) {
        entryPoint = _entryPoint;
        _entryPointV08DomainSeparatorV4 = IEntryPoint_v08(entryPoint).getDomainSeparatorV4();
    }

    function getDomainSeparatorV4() public view returns (bytes32) {
        return _entryPointV08DomainSeparatorV4;
    }

    function setSessionKey(address sessionKey, uint32 validUntil, bytes32 merkleRoot) external {
        address walletAddress = msg.sender;
        SessionKeyInfo storage sessionKeyInfo = sessionKeys[walletAddress];
        sessionKeyInfo.validUntil = validUntil;
        sessionKeyInfo.merkleRoot = merkleRoot;
        sessionKeyInfo.sessionKey = sessionKey;
        emit SessionKeySeted(walletAddress, sessionKey, validUntil, merkleRoot);
    }

    function _validateTarget(bytes32[] memory leaves, address target, bytes memory data)
        private
        pure
        returns (bool isValid)
    {
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32 leaf = leaves[i];
            uint8 leafType = uint8(uint256(leaf) >> (31 * 8));
            if (leafType == 0x01 || leafType == 0x02) {
                address approvedTarget = address(uint160(uint256(leaf) >> (11 * 8) & type(uint160).max));
                if (leafType == 0x01) {
                    // keccak256(bytes32(abi.encodePacked(0x01, approvedTargetAddress(bytes20))))
                    if (approvedTarget == target) {
                        return true;
                    }
                } else {
                    // keccak256(bytes32(abi.encodePacked(0x02, approvedTargetAddress(bytes20), method(bytes4)))
                    if (approvedTarget != target) {
                        continue;
                    }
                    bytes4 method = bytes4(uint32(uint256(leaf) >> (7 * 8) & type(uint32).max));
                    if (method == bytes4(data)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    function _validateEIP1271Target(bytes32[] memory leaves, address target) private pure returns (bool isValid) {
        for (uint256 i = 0; i < leaves.length; i++) {
            bytes32 leaf = leaves[i];
            uint8 leafType = uint8(uint256(leaf) >> (31 * 8));
            if (leafType == 0x04) {
                address approvedTarget = address(uint160(uint256(leaf) >> (11 * 8) & type(uint160).max));
                // keccak256(bytes32(abi.encodePacked(0x04, approvedTargetAddress(bytes20))))
                if (approvedTarget == target) {
                    return true;
                }
            }
        }
        return false;
    }

    function _validateSessionKey(PackedUserOperation calldata userOp, bytes calldata sessionKeyData)
        private
        view
        returns (uint256 validationData)
    {
        bytes32[] memory proof;
        bool[] memory proofFlags;
        bytes32[] memory leaves;
        (proof, proofFlags, leaves) = abi.decode(sessionKeyData, (bytes32[], bool[], bytes32[]));

        bytes32[] memory leavesHash = new bytes32[](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            leavesHash[i] = keccak256(abi.encodePacked(leaves[i]));
        }

        address walletAddress = msg.sender;
        bytes32 merkleRoot = sessionKeys[walletAddress].merkleRoot;
        if (merkleRoot == bytes32(0)) {
            return SIG_VALIDATION_FAILED;
        }
        if (MerkleProof.multiProofVerify(proof, proofFlags, merkleRoot, leavesHash) == false) {
            return SIG_VALIDATION_FAILED;
        }

        bytes4 selector = bytes4(userOp.callData);

        if (IStandardExecutor.execute.selector == selector) {
            // function execute(address target, uint256 value, bytes calldata data)
            (address target, uint256 value, bytes memory data) =
                abi.decode(userOp.callData[4:], (address, uint256, bytes));
            (value);
            if (_validateTarget(leaves, target, data) == false) {
                return SIG_VALIDATION_FAILED;
            }
        } else if (IStandardExecutor.executeBatch.selector == selector) {
            // function executeBatch(Execution[] calldata executions)
            (Execution[] memory executions) = abi.decode(userOp.callData[4:], (Execution[]));
            for (uint256 i = 0; i < executions.length; i++) {
                (address target, uint256 value, bytes memory data) =
                    (executions[i].target, executions[i].value, executions[i].data);
                (value);
                if (_validateTarget(leaves, target, data) == false) {
                    return SIG_VALIDATION_FAILED;
                }
            }
        }
        return uint256(sessionKeys[walletAddress].validUntil) << 160;
    }

    function _validateEIP1271SessionKey(address caller, bytes calldata sessionKeyData)
        private
        view
        returns (bool isValid)
    {
        bytes32[] memory proof;
        bool[] memory proofFlags;
        bytes32[] memory leaves;
        (proof, proofFlags, leaves) = abi.decode(sessionKeyData, (bytes32[], bool[], bytes32[]));

        bytes32[] memory leavesHash = new bytes32[](leaves.length);
        for (uint256 i = 0; i < leaves.length; i++) {
            leavesHash[i] = keccak256(abi.encodePacked(leaves[i]));
        }

        address walletAddress = msg.sender;
        bytes32 merkleRoot = sessionKeys[walletAddress].merkleRoot;
        if (merkleRoot == bytes32(0)) {
            return false;
        }
        if (MerkleProof.multiProofVerify(proof, proofFlags, merkleRoot, leavesHash) == false) {
            return false;
        }

        if (_validateEIP1271Target(leaves, caller) == false) {
            return false;
        }
        return block.timestamp < sessionKeys[walletAddress].validUntil;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, bytes calldata validatorSignature)
        external
        view
        override
        returns (uint256 validationData)
    {
        uint8 signatureType;
        bytes calldata signature;
        (signatureType, validationData, signature) = ValidatorSigDecoder.decodeValidatorSignature(validatorSignature);

        bytes32 hash;
        if (signatureType == 0x0 || signatureType == 0x2 || signatureType == 0x4) {
            // For types 0x0 0x2 0x4, use userOpHash directly
            hash = userOpHash;
        } else if (signatureType == 0x1 || signatureType == 0x3) {
            // For types 0x1 and 0x3, create a new PackedUserOperationWithValidatorData
            ValidationData memory _validationData = _parseValidationData(validationData);
            PackedUserOpWithValidTimeRange memory userOpWithValidTimeRange = PackedUserOpWithValidTimeRange({
                sender: userOp.sender,
                nonce: userOp.nonce,
                initCode: userOp.initCode,
                callData: userOp.callData,
                accountGasLimits: userOp.accountGasLimits,
                preVerificationGas: userOp.preVerificationGas,
                gasFees: userOp.gasFees,
                paymasterAndData: userOp.paymasterAndData,
                validUntil: _validationData.validUntil,
                validAfter: _validationData.validAfter
            });
            // Get the typed data hash
            hash = getTypedDataHash(userOpWithValidTimeRange);
        }

        bytes32 recovered;
        bool success;
        if (signatureType == 0x4) {
            (recovered, success) = recover(signatureType, hash, signature[0:65]);
        } else {
            (recovered, success) = recover(signatureType, hash, signature);
        }
        if (!success) {
            return SIG_VALIDATION_FAILED;
        }
        if (signatureType == 0x4) {
            return _validateSessionKey(userOp, signature[65:]);
        } else {
            bool ownerCheck = _isOwner(recovered);
            if (!ownerCheck) {
                return SIG_VALIDATION_FAILED;
            }
            return validationData;
        }
    }

    function validateSignature(address sender, bytes32 rawHash, bytes calldata validatorSignature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        uint8 signatureType;
        bytes calldata signature;
        uint256 validationData;
        (signatureType, validationData, signature) = ValidatorSigDecoder.decodeValidatorSignature(validatorSignature);

        bytes32 hash = _pack1271SignatureHash(rawHash, signatureType, validationData);
        bytes32 recovered;
        bool success;

        if (signatureType == 0x4) {
            (recovered, success) = recover(signatureType, hash, signature[0:65]);
        } else {
            (recovered, success) = recover(signatureType, hash, signature);
        }

        if (!success) {
            return INVALID_ID;
        }
        if (signatureType == 0x4) {
            if (_validateEIP1271SessionKey(sender, signature[65:]) == false) {
                return INVALID_ID;
            }
        } else {
            bool ownerCheck = _isOwner(recovered);
            if (!ownerCheck) {
                return INVALID_ID;
            }
            if (validationData > 0) {
                ValidationData memory _validationData = _parseValidationData(validationData);
                bool outOfTimeRange =
                    (block.timestamp > _validationData.validUntil) || (block.timestamp < _validationData.validAfter);
                if (outOfTimeRange) {
                    return INVALID_TIME_RANGE;
                }
            }
        }
        return MAGICVALUE;
    }

    function _pack1271SignatureHash(bytes32 hash, uint8 signatureType, uint256 validationData)
        internal
        pure
        returns (bytes32)
    {
        if (signatureType == 0x0 || signatureType == 0x2 || signatureType == 0x4) {
            // For types 0x0 0x2 0x4, return hash as is, userOpHash can be generated using eth_signTypedData_v4, therefore no need to use toEthSignedMessageHash
            return hash;
        } else if (signatureType == 0x1 || signatureType == 0x3) {
            // For types 0x1 and 0x3, return keccak256(abi.encodePacked(hash, validationData))
            return keccak256(abi.encodePacked(hash, validationData));
        } else {
            revert Errors.INVALID_SIGNTYPE();
        }
    }

    function _isOwner(bytes32 recovered) private view returns (bool isOwner) {
        return IOwnable(address(msg.sender)).isOwner(recovered);
    }

    function recover(uint8 signatureType, bytes32 rawHash, bytes calldata rawSignature)
        internal
        view
        returns (bytes32 recovered, bool success)
    {
        if (signatureType == 0x0 || signatureType == 0x1) {
            //ecdas recover
            (address recoveredAddr, ECDSA.RecoverError error,) = ECDSA.tryRecover(rawHash, rawSignature);
            if (error != ECDSA.RecoverError.NoError) {
                success = false;
            } else {
                success = true;
            }
            recovered = recoveredAddr.toBytes32();
        } else if (signatureType == 0x2 || signatureType == 0x3) {
            bytes32 publicKey = WebAuthn.recover(rawHash, rawSignature);
            if (publicKey == 0) {
                recovered = publicKey;
                success = false;
            } else {
                recovered = publicKey;
                success = true;
            }
        } else {
            revert Errors.INVALID_SIGNTYPE();
        }
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IValidator).interfaceId;
    }

    function Init(bytes calldata) external override {}

    function DeInit() external override {}

    /**
     * @dev Get the typed data hash for a PackedUserOpWithValidTimeRange
     * @param userOpWithValidTimeRange The user operation with validator data
     * @return The typed data hash
     */
    function getTypedDataHash(PackedUserOpWithValidTimeRange memory userOpWithValidTimeRange)
        public
        view
        returns (bytes32)
    {
        return MessageHashUtils.toTypedDataHash(getDomainSeparatorV4(), userOpWithValidTimeRange.hash());
    }
}
