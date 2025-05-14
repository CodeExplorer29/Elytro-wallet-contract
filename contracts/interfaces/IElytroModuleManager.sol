// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IModuleManager} from "@ElytroWalletCore/contracts/interface/IModuleManager.sol";

interface IElytroModuleManager is IModuleManager {
    function installModule(bytes calldata moduleAndData) external;
}
