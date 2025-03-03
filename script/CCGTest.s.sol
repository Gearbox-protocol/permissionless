// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {CCGHelper} from "../contracts/test/helpers/CCGHelper.sol";
import {GlobalSetup} from "../contracts/test/helpers/GlobalSetup.sol";
import {TestKeys} from "../contracts/test/helpers/TestKeys.sol";

import {AP_POOL_FACTORY} from "../contracts/libraries/ContractLiterals.sol";
import {CrossChainCall} from "../contracts/interfaces/Types.sol";

contract CCGTestScript is Script, GlobalSetup {
    function run() public {
        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        TestKeys testKeys = new TestKeys();

        uint256 len = testKeys.initialSigners().length;
        address[] memory initialSigners = new address[](len);

        for (uint256 i = 0; i < len; i++) {
            initialSigners[i] = testKeys.initialSigners()[i].addr;
        }

        _attachGlobalContracts(initialSigners, testKeys.threshold(), testKeys.dao().addr);

        CrossChainCall[] memory calls = new CrossChainCall[](1);
        calls[0] = _generateDeploySystemContractCall(AP_POOL_FACTORY, 3_10, true);

        _submitBatch("Testtt", calls);
    }
}
