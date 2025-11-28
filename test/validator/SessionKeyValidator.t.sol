// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IElytro} from "@source/interfaces/IElytro.sol";
import {TypeConversion} from "@source/libraries/TypeConversion.sol";
import {DefaultCallbackHandler} from "@source/abstract/DefaultCallbackHandler.sol";
import {ElytroInstence} from "../elytro/base/ElytroInstence.sol";
import {SIG_VALIDATION_FAILED} from "@account-abstraction/contracts/core/Helpers.sol";
import {ElytroDefaultValidator} from "@source/validator/ElytroDefaultValidator.sol";
import {ElytroValidatorManager} from "@source/abstract/ElytroValidatorManager.sol";
import {ValidatorManager} from "@elytro-wallet-core/contracts/base/ValidatorManager.sol";
import {SessionKeyValidator} from "@source/validator/SessionKeyValidator/SessionKeyValidator.sol";
import {PackedUserOperation} from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";
import {IStandardExecutor, Execution} from "@elytro-wallet-core/contracts/interface/IStandardExecutor.sol";
import {UserOpHelper} from "../helper/UserOpHelper.t.sol";
import {TokenERC20} from "../dev/tokens/TokenERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@account-abstraction/contracts/core/Helpers.sol";

contract SessionKeyValidatorTest is Test, UserOpHelper {
    using TypeConversion for address;

    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // Constants indicating different invalid states
    bytes4 internal constant INVALID_ID = 0xffffffff;
    bytes4 internal constant INVALID_TIME_RANGE = 0xfffffffe;
    ElytroDefaultValidator elytroDefaultValidator;
    SessionKeyValidator sessionKeyValidator;

    address public owner;
    uint256 public ownerKey;
    address public sessionOwner;
    uint256 public sessionOwnerKey;

    ElytroInstence public elytroInstence;
    IElytro elytro;
    TokenERC20 public testToken;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        (sessionOwner, sessionOwnerKey) = makeAddrAndKey("sessionOwner");
        bytes[] memory modules = new bytes[](0);
        bytes[] memory hooks = new bytes[](0);
        bytes32 salt = bytes32(0);
        DefaultCallbackHandler defaultCallbackHandler = new DefaultCallbackHandler();
        bytes32[] memory owners = new bytes32[](1);
        owners[0] = (owner).toBytes32();

        elytroInstence = new ElytroInstence(address(defaultCallbackHandler), owners, modules, hooks, salt);
        elytroDefaultValidator = elytroInstence.defaultValidator();
        sessionKeyValidator = new SessionKeyValidator();
        entryPoint = elytroInstence.entryPoint();
        elytro = elytroInstence.elytro();
        assertEq(elytro.isOwner(owner.toBytes32()), true);

        vm.deal(address(elytro), 1000 ether);

        testToken = new TokenERC20(18);
        assertEq(0xc7183455a4C133Ae270771860664b6B7ec320bB1, address(testToken));
        testToken.transfer(address(elytro), 1000 ether);
    }

    // Helper function to get userOpHash similar to EntryPoint's getUserOpHash
    function getUserOpHash(PackedUserOperation memory userOp) internal view returns (bytes32) {
        return entryPoint.getUserOpHash(userOp);
    }

    function _installSessionKeyValidator() private {
        /**
         * function installValidator(bytes calldata validatorAndData)
         */
        //  (address sessionKey, uint32 validUntil, bytes32 merkleRoot)
        uint32 validUntil = uint32(block.timestamp + 1 days);
        /*
            const rawElements = [
                "0x02c7183455a4c133ae270771860664b6b7ec320bb1a9059cbb00000000000000",
                "0x02c7183455a4c133ae270771860664b6b7ec320bb1095ea7b300000000000000",
                "0x02c7183455a4c133ae270771860664b6b7ec320bb123b872dd00000000000000",
            ];
            "root": "0xe57e94e43fabd0f1378d9159f22fda1e1b0f20da169360e8690d5307a05cee48",
            "leaves": [
                "0x1b31296affa227e9671e2fb318b0c0a0567ec1b75bcf535e8c5d5d015290bd4c",
                "0x4684cf71061cb00a92f1e697f7a53defa8ea83c9138fbaa461f72b3be43c18a2"
            ],
            "proof": [
                "0xd3d64f0ae508465daf42a4b6c770125e380a9430211781d9a99ce22a19740334"
            ],
            "proofFlags": [
                true,
                false
            ]
        
         */
        bytes32 merkleRoot = 0xe57e94e43fabd0f1378d9159f22fda1e1b0f20da169360e8690d5307a05cee48;

        bytes memory _calldata = abi.encodeWithSelector(
            ElytroValidatorManager.installValidator.selector,
            abi.encodePacked(address(sessionKeyValidator), abi.encode(sessionOwner, validUntil, merkleRoot))
        );

        bytes memory callData =
            abi.encodeWithSelector(IStandardExecutor.execute.selector, address(elytro), 0, _calldata);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(elytro),
            nonce: 0,
            initCode: new bytes(0),
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 100000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        address[] memory validators = ElytroValidatorManager(address(elytro)).listValidator();
        assertEq(validators.length, 1);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        userOp.signature = signUserOp(userOp, ownerKey, address(elytroDefaultValidator));
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(owner));
        validators = ElytroValidatorManager(address(elytro)).listValidator();
        assertEq(validators.length, 2);
    }

    function test_installSessionKeyValidator() public {
        _installSessionKeyValidator();
    }

    function test_uninstallSessionKeyValidator() public {
        _installSessionKeyValidator();

        address[] memory validators = ElytroValidatorManager(address(elytro)).listValidator();
        assertEq(validators.length, 2);

        /**
         * function uninstallValidator(address validator)
         */
        bytes memory _calldata =
            abi.encodeWithSelector(ValidatorManager.uninstallValidator.selector, address(sessionKeyValidator));

        bytes memory callData =
            abi.encodeWithSelector(IStandardExecutor.execute.selector, address(elytro), 0, _calldata);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(elytro),
            nonce: 1,
            initCode: new bytes(0),
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 100000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        userOp.signature = signUserOp(userOp, ownerKey, address(elytroDefaultValidator));
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(owner));
        validators = ElytroValidatorManager(address(elytro)).listValidator();
        assertEq(validators.length, 1);
    }

    function test_ValidateUserOp() public {
        _installSessionKeyValidator();

        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({
            target: address(testToken),
            value: 0,
            data: abi.encodeWithSelector(ERC20.transfer.selector, address(0x12345), 5 ether)
        });
        executions[1] = Execution({
            target: address(testToken),
            value: 0,
            data: abi.encodeWithSelector(ERC20.approve.selector, address(0x12345), 10 ether)
        });

        bytes memory callData = abi.encodeWithSelector(IStandardExecutor.executeBatch.selector, executions);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(elytro),
            nonce: 1,
            initCode: new bytes(0),
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(1000000), uint128(1000000))),
            preVerificationGas: 100000,
            gasFees: bytes32(abi.encodePacked(uint128(1 gwei), uint128(1 gwei))),
            paymasterAndData: new bytes(0),
            signature: new bytes(0)
        });
        bytes32 userOpHash = getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionOwnerKey, userOpHash);
        bytes memory opSig;
        bytes memory proofData;
        {
            bytes32[] memory proof = new bytes32[](1);
            proof[0] = 0xd3d64f0ae508465daf42a4b6c770125e380a9430211781d9a99ce22a19740334;
            bool[] memory proofFlags = new bool[](2);
            proofFlags[0] = true;
            proofFlags[1] = false;
            bytes32[] memory leaves = new bytes32[](2);
            leaves[0] = bytes32(abi.encodePacked(uint8(2), address(testToken), ERC20.transfer.selector));
            leaves[1] = bytes32(abi.encodePacked(uint8(2), address(testToken), ERC20.approve.selector));
            proofData = abi.encode(proof, proofFlags, leaves);
        }
        bytes memory validatorSignature = abi.encodePacked(abi.encodePacked(r, s, v), proofData);
        bytes4 signatureLength = bytes4(uint32(validatorSignature.length));
        opSig = abi.encodePacked(address(sessionKeyValidator), signatureLength, validatorSignature);
        userOp.signature = opSig;
        // Validate
        vm.startPrank(address(elytro));
        uint256 validationData = sessionKeyValidator.validateUserOp(userOp, userOpHash, validatorSignature);
        ValidationData memory data = _parseValidationData(validationData);
        bool outOfTimeRange = block.timestamp > data.validUntil || block.timestamp <= data.validAfter;
        assertEq(outOfTimeRange, false);
        vm.stopPrank();
    }
}
