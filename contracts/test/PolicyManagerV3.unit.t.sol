// SPDX-License-Identifier: UNLICENSED
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {PolicyManagerV3Harness, Policy} from "./PolicyManagerV3Harness.sol";
import {PERCENTAGE_FACTOR} from "@gearbox-protocol/core-v2/contracts/libraries/Constants.sol";

// MOCKS
import {AddressProviderV3ACLMock} from
    "@gearbox-protocol/core-v3/contracts/test/mocks/core/AddressProviderV3ACLMock.sol";
import "@gearbox-protocol/core-v3/contracts/test/lib/constants.sol";

contract PolicyManagerV3UnitTest is Test {
    AddressProviderV3ACLMock public addressProvider;

    PolicyManagerV3Harness public policyManager;

    event SetPolicy(bytes32 indexed policyHash, bool enabled);
    event SetGroup(address indexed contractAddress, string indexed group);

    function setUp() public {
        vm.prank(CONFIGURATOR);
        addressProvider = new AddressProviderV3ACLMock();

        policyManager = new PolicyManagerV3Harness(address(addressProvider));
    }

    ///
    ///
    ///  TESTS
    ///
    ///

    /// @dev U:[PM-1]: setPolicy and getPolicy work correctly
    function test_U_PM_01_setPolicy_getPolicy_work_correctly() public {
        uint256[] memory setValues = new uint256[](1);
        setValues[0] = 15;

        Policy memory policy = Policy({
            enabled: false,
            admin: FRIEND,
            delay: 1 days,
            checkInterval: true,
            checkSet: true,
            intervalMinValue: 10,
            intervalMaxValue: 20,
            setValues: setValues
        });

        vm.expectRevert(CallerNotConfiguratorException.selector);
        vm.prank(USER);
        policyManager.setPolicy("TEST", policy);

        vm.expectEmit(true, false, false, true);
        emit SetPolicy("TEST", true);

        vm.prank(CONFIGURATOR);
        policyManager.setPolicy("TEST", policy);

        Policy memory policy2 = policyManager.getPolicy("TEST");

        assertTrue(policy2.enabled, "Enabled not set by setPolicy");

        assertEq(policy2.admin, FRIEND, "Admin was not set correctly");

        assertEq(policy2.intervalMinValue, 10, "minValue is incorrect");

        assertEq(policy2.intervalMaxValue, 20, "maxValue is incorrect");

        assertEq(policy2.setValues.length, 1, "Set length incorrect");

        assertEq(policy2.setValues[0], 15, "Set value incorrect");
    }

    /// @dev U:[PM-2]: checkPolicy fails on disabled policy
    function test_U_PM_02_checkPolicy_false_on_disabled() public {
        uint256[] memory setValues = new uint256[](1);
        setValues[0] = 15;

        Policy memory policy = Policy({
            enabled: false,
            admin: FRIEND,
            delay: 1 days,
            checkInterval: true,
            checkSet: true,
            intervalMinValue: 10,
            intervalMaxValue: 20,
            setValues: setValues
        });

        vm.prank(CONFIGURATOR);
        policyManager.setPolicy("TEST", policy);

        vm.expectEmit(true, false, false, true);
        emit SetPolicy("TEST", false);

        vm.prank(CONFIGURATOR);
        policyManager.disablePolicy("TEST");

        vm.prank(FRIEND);
        assertTrue(!policyManager.checkPolicy("TEST", 15));
    }

    /// @dev U:[PM-3]: checkPolicy exactValue works correctly
    function test_U_PM_03_checkPolicy_interval_works_correctly(uint256 minValue, uint256 maxValue, uint256 newValue)
        public
    {
        uint256[] memory setValues = new uint256[](1);
        setValues[0] = 15;

        Policy memory policy = Policy({
            enabled: false,
            admin: FRIEND,
            delay: 1 days,
            checkInterval: true,
            checkSet: false,
            intervalMinValue: minValue,
            intervalMaxValue: maxValue,
            setValues: setValues
        });

        vm.prank(CONFIGURATOR);
        policyManager.setPolicy("TEST", policy);

        vm.prank(FRIEND);
        assertTrue((newValue <= maxValue && newValue >= minValue) || !policyManager.checkPolicy("TEST", newValue));
    }

    /// @dev U:[PM-4]: checkPolicy minValue works correctly
    function test_U_PM_04_checkPolicy_set_works_correctly(uint256 setValue0, uint256 setValue1, uint256 newValue)
        public
    {
        uint256[] memory setValues = new uint256[](2);
        setValues[0] = setValue0;
        setValues[1] = setValue1;

        Policy memory policy = Policy({
            enabled: false,
            admin: FRIEND,
            delay: 1 days,
            checkInterval: false,
            checkSet: true,
            intervalMinValue: 0,
            intervalMaxValue: 0,
            setValues: setValues
        });

        vm.prank(CONFIGURATOR);
        policyManager.setPolicy("TEST", policy);

        vm.prank(FRIEND);
        assertTrue(newValue == setValue0 || newValue == setValue1 || !policyManager.checkPolicy("TEST", newValue));
    }

    /// @dev U:[PM-05]: checkPolicy returns false on caller not being admin
    function test_U_PM_05_checkPolicy_returns_false_on_wrong_caller() public {
        uint256[] memory setValues = new uint256[](1);
        setValues[0] = 15;

        Policy memory policy = Policy({
            enabled: false,
            admin: FRIEND,
            delay: 1 days,
            checkInterval: true,
            checkSet: false,
            intervalMinValue: 10,
            intervalMaxValue: 20,
            setValues: setValues
        });

        vm.prank(CONFIGURATOR);
        policyManager.setPolicy("TEST", policy);

        vm.prank(USER);
        assertTrue(!policyManager.checkPolicy("TEST", 15));

        vm.prank(FRIEND);
        assertTrue(policyManager.checkPolicy("TEST", 15));
    }
}
