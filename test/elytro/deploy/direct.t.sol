// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {ElytroDefaultValidator} from "@source/validator/ElytroDefaultValidator.sol";
import {EntryPoint} from "@account-abstraction/contracts/core/EntryPoint.sol";

import "@source/libraries/TypeConversion.sol";
import "@source/dev/tokens/TokenERC20.sol";
import "@source/abstract/DefaultCallbackHandler.sol";
import "@source/Elytro.sol";

contract DeployDirectTest is Test {
    // Alice's address and private key (EOA with no initial contract code).
    address payable ALICE_ADDRESS = payable(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    uint256 constant ALICE_PK = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    using TypeConversion for address;

    Elytro elytro;
    EntryPoint public entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        elytro = new Elytro(address(entryPoint), address(new ElytroDefaultValidator()));
    }

    function test_Deploy() public {
        vm.signAndAttachDelegation(address(elytro), ALICE_PK);
        bytes memory code = address(ALICE_ADDRESS).code;
        require(code.length > 0, "no code written to Alice");
        bytes[] memory modules = new bytes[](0);
        bytes[] memory hooks = new bytes[](0);
        DefaultCallbackHandler defaultCallbackHandler = new DefaultCallbackHandler();
        Elytro(ALICE_ADDRESS).initialize(address(defaultCallbackHandler), modules, hooks);
        assertEq(Elytro(ALICE_ADDRESS).isOwner(address(ALICE_ADDRESS).toBytes32()), true);
        assertEq(Elytro(ALICE_ADDRESS).isOwner(address(0x1111).toBytes32()), false);
    }
}
