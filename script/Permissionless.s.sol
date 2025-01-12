// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {CCGHelper} from "../contracts/test/helpers/CCGHelper.sol";
import {InstanceManagerHelper} from "../contracts/test/helpers/InstanceManagerHelper.sol";

contract PermissionlessScript is Script, InstanceManagerHelper {
    function setUp() public {}

    function run() public {
        vm.broadcast();

        _setUpInstanceManager();
        // // Set up instance manager and initial contracts
        // _setUpInstanceManager();
        // _setupInitialSystemContracts();

        // // Configure instance
        // _setupPriceFeedStore();

        vm.stopBroadcast();
    }
}
