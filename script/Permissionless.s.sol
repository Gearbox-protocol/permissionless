// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import {CCGHelper} from "../contracts/test/helpers/CCGHelper.sol";
import {GlobalSetup} from "../contracts/test/helpers/GlobalSetup.sol";
import {TestKeys} from "../contracts/test/helpers/TestKeys.sol";

contract PermissionlessScript is Script, GlobalSetup {
    function run() public {
        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        // Setup test keys
        TestKeys testKeys = new TestKeys();

        if (!_isTestMode()) {
            // Print debug info
            testKeys.printKeys();
        }

        address[] memory addressesToFund = new address[](testKeys.initialSigners().length + 2);
        for (uint256 i = 0; i < testKeys.initialSigners().length; i++) {
            addressesToFund[i] = testKeys.initialSigners()[i].addr;
        }
        addressesToFund[testKeys.initialSigners().length] = testKeys.auditor().addr;
        addressesToFund[testKeys.initialSigners().length + 1] = testKeys.dao().addr;

        _fundActors(addressesToFund, 1 ether);
        _deployGlobalContracts(
            testKeys.initialSigners(), testKeys.auditor(), "Initial Auditor", testKeys.threshold(), testKeys.dao().addr
        );

        vm.stopBroadcast();

        _exportJson();
    }
}
