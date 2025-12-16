// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "@source/modules/socialRecovery/guardians/ZKPassportGuardian.sol";
import "@source/modules/socialRecovery/guardians/ZKPassportGuardianFactory.sol";
import "./DeployHelper.sol";

/// @notice Deploys the ZKPassport guardian implementation and its factory.
contract CreateZKPassportGuardian is Script, DeployHelper {
    function run() public {
        vm.startBroadcast(privateKey);

        address guardianImpl = deploy("ZKPassportGuardian", type(ZKPassportGuardian).creationCode);
        bytes memory factoryInitCode =
            abi.encodePacked(type(ZKPassportGuardianFactory).creationCode, abi.encode(guardianImpl));
        deploy("ZKPassportGuardianFactory", factoryInitCode);
    }
}
