// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {ConfigurationTestHelper} from "./ConfigurationTestHelper.sol";
import {IPriceOracleConfigureActions} from "../../interfaces/factories/IPriceOracleConfigureActions.sol";
import {IPriceOracleEmergencyConfigureActions} from
    "../../interfaces/factories/IPriceOracleEmergencyConfigureActions.sol";
import {IPriceOracleV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {IPriceFeedStore} from "../../interfaces/IPriceFeedStore.sol";
import {MockPriceFeed} from "../mocks/MockPriceFeed.sol";
import {IContractsRegister} from "../../interfaces/IContractsRegister.sol";
import {IAddressProvider} from "../../interfaces/IAddressProvider.sol";
import {AP_PRICE_FEED_STORE, NO_VERSION_CONTROL} from "../../libraries/ContractLiterals.sol";

contract PriceOracleConfigurationUnitTest is ConfigurationTestHelper {
    address private _target;
    address private _priceFeedStore;
    address private _priceOracle;

    function setUp() public override {
        super.setUp();

        _target = address(new MockPriceFeed());
        _priceOracle = IContractsRegister(marketConfigurator.contractsRegister()).getPriceOracle(address(pool));
        _priceFeedStore = IAddressProvider(addressProvider).getAddressOrRevert(AP_PRICE_FEED_STORE, NO_VERSION_CONTROL);

        _addUSDC();
    }

    /// REGULAR CONFIGURATION TESTS ///

    function test_PO_01_setPriceFeed() public {
        address token = USDC;
        address priceFeed = address(new MockPriceFeed());
        uint32 stalenessPeriod = 3600;

        vm.mockCall(
            _priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );

        vm.mockCall(
            _priceFeedStore,
            abi.encodeCall(IPriceFeedStore.getStalenessPeriod, (priceFeed)),
            abi.encode(stalenessPeriod)
        );

        vm.expectCall(_priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, stalenessPeriod)));

        vm.prank(admin);
        marketConfigurator.configurePriceOracle(
            address(pool), abi.encodeCall(IPriceOracleConfigureActions.setPriceFeed, (token, priceFeed))
        );

        assertEq(IPriceOracleV3(_priceOracle).priceFeeds(token), priceFeed, "Incorrect price feed");
    }

    function test_PO_02_setReservePriceFeed() public {
        address token = USDC;
        address priceFeed = address(new MockPriceFeed());
        uint32 stalenessPeriod = 3600;

        vm.mockCall(
            _priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );

        vm.mockCall(
            _priceFeedStore,
            abi.encodeCall(IPriceFeedStore.getStalenessPeriod, (priceFeed)),
            abi.encode(stalenessPeriod)
        );

        vm.expectCall(
            _priceOracle, abi.encodeCall(IPriceOracleV3.setReservePriceFeed, (token, priceFeed, stalenessPeriod))
        );

        vm.prank(admin);
        marketConfigurator.configurePriceOracle(
            address(pool), abi.encodeCall(IPriceOracleConfigureActions.setReservePriceFeed, (token, priceFeed))
        );

        assertEq(IPriceOracleV3(_priceOracle).reservePriceFeeds(token), priceFeed, "Incorrect reserve price feed");
    }

    /// EMERGENCY CONFIGURATION TESTS ///

    function test_PO_03_emergency_setPriceFeed() public {
        address token = USDC;
        address priceFeed = address(new MockPriceFeed());
        uint32 stalenessPeriod = 3600;

        vm.mockCall(
            _priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );

        vm.mockCall(
            _priceFeedStore,
            abi.encodeCall(IPriceFeedStore.getStalenessPeriod, (priceFeed)),
            abi.encode(stalenessPeriod)
        );

        vm.mockCall(
            _priceFeedStore,
            abi.encodeCall(IPriceFeedStore.getAllowanceTimestamp, (token, priceFeed)),
            abi.encode(block.timestamp - 1 days - 1)
        );

        vm.expectCall(_priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, stalenessPeriod)));

        vm.prank(emergencyAdmin);
        marketConfigurator.emergencyConfigurePriceOracle(
            address(pool), abi.encodeCall(IPriceOracleEmergencyConfigureActions.setPriceFeed, (token, priceFeed))
        );

        assertEq(IPriceOracleV3(_priceOracle).priceFeeds(token), priceFeed, "Incorrect price feed");
    }
}
