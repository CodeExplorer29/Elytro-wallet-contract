// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "@source/hooks/securityHook/SecurityHook.sol";
import {Solenv} from "@solenv/Solenv.sol";
import "./DeployHelper.sol";

contract SecurityHookDeployer is Script, DeployHelper {
    address public hookOwner;
    address public hookSigner;
    address public securityHook;

    function run() public {
        // Load backend env vars so the deploy helper can also persist addresses.
        Solenv.config(".env_backend");

        hookOwner = deployer;
        hookSigner = vm.envAddress("SECURITY_HOOK_SIGNER");
        require(hookSigner != address(0), "SECURITY_HOOK_SIGNER not provided");

        vm.startBroadcast(privateKey);
        string memory networkName = NetWorkLib.getNetworkName();
        console.log("Deploying SecurityHook on", networkName);
        deploySecurityHook();
        vm.stopBroadcast();
    }

    function deploySecurityHook() internal {
        securityHook =
            deploy("SecurityHook", abi.encodePacked(type(SecurityHook).creationCode, abi.encode(hookOwner, hookSigner)));
        console.log("SecurityHook deployed at:", securityHook);
    }
}
