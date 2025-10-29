// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IHook, PackedUserOperation} from "@elytro-wallet-core/contracts/interface/IHook.sol";
import {IStandardExecutor} from "@elytro-wallet-core/contracts/interface/IStandardExecutor.sol";
import {IHookManager} from "@elytro-wallet-core/contracts/interface/IHookManager.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title SecurityHook
 * @notice A security enhancement module that allows users to delegate security controls to trusted organizations
 * @dev This contract implements additional security measures for wallet transactions through trusted verification
 *
 * The SecurityHook enables users to:
 * 1. Add an extra layer of security through mandatory two-factor authentication (2FA)
 * 2. Require verification (email, SMS, or Google Authenticator) for transactions
 * 3. Set up conditional verifications (e.g., 2FA for transactions exceeding $1000/day)
 *
 * Safety Features:
 * - Users can force-uninstall the hook if verification services become unavailable
 * - Implementation of a safety delay period through forcePreUninstall()
 * - After the safety delay (forceUninstallAfter) expires, users can remove the hook without verification
 * - This prevents permanent wallet lockout in case of lost 2FA or unresponsive verification services
 */
contract SecurityHook is IHook, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    event signerAdded(address indexed signer);
    event signerRemoved(address indexed signer);
    event forceUninstallRequested(address indexed user, uint64 forceUninstallAfter);

    struct UserData {
        bool initialized;
        /**
         * @notice The safetyDelay specifies a mandatory waiting time before force-uninstalling this Hook
         * if verification methods (e.g., email, SMS) or server responses are unavailable.
         */
        uint32 safetyDelay;
        /**
         * @notice After this timestamp, the user can force-uninstall this Hook without verification.
         */
        uint64 forceUninstallAfter;
    }

    mapping(address => bool) public signers;
    mapping(address => UserData) public userData;

    constructor(address initialOwner, address initialSigner) Ownable(initialOwner) {
        signers[initialSigner] = true;
        emit signerAdded(initialSigner);
    }

    function addSigner(address signer) external onlyOwner {
        signers[signer] = true;
        emit signerAdded(signer);
    }

    function removeSigner(address signer) external onlyOwner {
        signers[signer] = false;
        emit signerRemoved(signer);
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IHook).interfaceId;
    }

    function Init(bytes calldata data) external override {
        UserData storage _userData = userData[msg.sender];
        require(_userData.initialized == false, "SecurityHook: already initialized");
        _userData.initialized = true;
        _userData.forceUninstallAfter = 0;
        uint32 _safetyDelay = uint32(bytes4(data[:4]));
        require(_safetyDelay > 0 && _safetyDelay < 365 days, "SecurityHook: invalid safetyDelay");
        _userData.safetyDelay = _safetyDelay;
    }

    function DeInit() external override {
        UserData storage _userData = userData[msg.sender];
        require(_userData.initialized == true, "SecurityHook: cannot deinit");
        delete userData[msg.sender];
    }

    function forcePreUninstall() external {
        UserData storage _userData = userData[msg.sender];
        require(_userData.initialized == true, "SecurityHook: not initialized");
        require(_userData.forceUninstallAfter == 0, "SecurityHook: already requested");
        uint64 _forceUninstallAfter = uint64(block.timestamp) + uint64(_userData.safetyDelay);
        _userData.forceUninstallAfter = _forceUninstallAfter;
        emit forceUninstallRequested(msg.sender, _forceUninstallAfter);
    }

    function preIsValidSignatureHook(bytes32 hash, bytes calldata hookSignature) external view override {
        address recoveredAddress = hash.toEthSignedMessageHash().recover(hookSignature);
        require(signers[recoveredAddress], "SecurityHook: invalid signature");
    }

    function preUserOpValidationHook(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds,
        bytes calldata hookSignature
    ) external view override {
        (missingAccountFunds);

        if (hookSignature.length > 0) {
            address recoveredAddress = userOpHash.toEthSignedMessageHash().recover(hookSignature);
            require(signers[recoveredAddress], "SecurityHook: invalid signature");
            return;
        }

        if (userOp.callData.length >= 4 && bytes4(userOp.callData[:4]) == IStandardExecutor.execute.selector) {
            (address target,, bytes memory subData) = abi.decode(userOp.callData[4:], (address, uint256, bytes));
            if (subData.length >= 4) {
                bytes4 methodId;
                assembly ("memory-safe") {
                    methodId := mload(add(subData, 0x20))
                }
                if (target == address(this)) {
                    // only allow to call `function forcePreUninstall() external`;
                    if (methodId == SecurityHook.forcePreUninstall.selector) {
                        // allow execution for forcePreUninstall without signature
                        return;
                    }
                } else if (target == msg.sender) {
                    // only allow to call `function uninstallHook(address hookAddress) external`;
                    if (methodId == IHookManager.uninstallHook.selector && subData.length == 36) {
                        address hookAddress;
                        assembly ("memory-safe") {
                            hookAddress := mload(add(subData, 0x24 /* 0x20+0x04 */ ))
                        }
                        // only allow if the hookAddress is this contract
                        if (hookAddress == address(this)) {
                            UserData storage _userData = userData[msg.sender];
                            require(_userData.initialized == true, "SecurityHook: not initialized");
                            require(_userData.forceUninstallAfter != 0, "SecurityHook: force-uninstall not requested");
                            // allow if the force-uninstall waiting time has passed
                            require(
                                block.timestamp >= _userData.forceUninstallAfter,
                                "SecurityHook: safety delay not passed"
                            );
                            // allow execution
                            return;
                        }
                    }
                }
            }
        }
        revert("SecurityHook: missing signature");
    }
}
