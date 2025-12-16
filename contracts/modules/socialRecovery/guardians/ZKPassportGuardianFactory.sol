// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "./ZKPassportGuardian.sol";

error ZKGuardianFactoryInvalidImplementation();

/**
 * @title ZKPassportGuardianFactory
 * @notice Deploys minimal proxy instances of {ZKPassportGuardian} via CREATE2 for deterministic addresses.
 */
contract ZKPassportGuardianFactory {
    using Clones for address;

    address public immutable implementation;

    event GuardianDeployed(
        address indexed wallet,
        bytes32 indexed uniqueIdentifier,
        address guardian,
        bytes32 salt
    );

    constructor(address implementation_) {
        if (implementation_ == address(0)) revert ZKGuardianFactoryInvalidImplementation();
        implementation = implementation_;
    }

    /**
     * @notice Deploys a guardian clone deterministically using CREATE2.
     * @param init Initialization payload forwarded to the guardian.
     * @param salt Extra entropy for the CREATE2 salt. Set to zero for default.
     */
    function deployGuardian(ZKPassportGuardianInit calldata init, bytes32 salt) external returns (address guardian) {
        bytes32 finalSalt = computeSalt(init.wallet, init.uniqueIdentifier, salt);
        guardian = implementation.cloneDeterministic(finalSalt);
        ZKPassportGuardian(guardian).initialize(init);
        emit GuardianDeployed(init.wallet, init.uniqueIdentifier, guardian, finalSalt);
    }

    function predictGuardianAddress(address wallet, bytes32 uniqueIdentifier, bytes32 salt)
        external
        view
        returns (address)
    {
        bytes32 finalSalt = computeSalt(wallet, uniqueIdentifier, salt);
        return implementation.predictDeterministicAddress(finalSalt);
    }

    function computeSalt(address wallet, bytes32 uniqueIdentifier, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(wallet, uniqueIdentifier, salt));
    }
}
