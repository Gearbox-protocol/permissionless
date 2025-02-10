// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {ConfigurationTestHelper} from "./ConfigurationTestHelper.sol";
import {ILossPolicy} from "@gearbox-protocol/core-v3/contracts/interfaces/base/ILossPolicy.sol";
import {DefaultLossPolicy} from "../../helpers/DefaultLossPolicy.sol";
import {IContractsRegister} from "../../interfaces/IContractsRegister.sol";

contract LossPolicyConfigurationUnitTest is ConfigurationTestHelper {
    address private _lossPolicy;

    function setUp() public override {
        super.setUp();
        _lossPolicy = IContractsRegister(marketConfigurator.contractsRegister()).getLossPolicy(address(pool));
    }

    /// REGULAR CONFIGURATION TESTS ///

    function test_LP_01_configure() public {
        vm.expectCall(_lossPolicy, abi.encodeCall(ILossPolicy.enable, ()));

        vm.prank(admin);
        marketConfigurator.configureLossPolicy(address(pool), abi.encodeCall(ILossPolicy.enable, ()));

        assertTrue(DefaultLossPolicy(_lossPolicy).enabled(), "Loss policy must be enabled");
    }

    /// EMERGENCY CONFIGURATION TESTS ///

    function test_LP_02_emergency_configure() public {
        vm.expectCall(_lossPolicy, abi.encodeCall(ILossPolicy.enable, ()));

        vm.prank(emergencyAdmin);
        marketConfigurator.emergencyConfigureLossPolicy(address(pool), abi.encodeCall(ILossPolicy.enable, ()));

        assertTrue(DefaultLossPolicy(_lossPolicy).enabled(), "Loss policy must be enabled");
    }
}
