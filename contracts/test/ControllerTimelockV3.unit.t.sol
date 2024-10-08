// SPDX-License-Identifier: UNLICENSED
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {ControllerTimelockV3} from "../market/ControllerTimelockV3.sol";

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

import {GeneralMock} from "@gearbox-protocol/core-v3/contracts/test/mocks/GeneralMock.sol";

import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {IPriceOracleV3, PriceFeedParams} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {PoolV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolV3.sol";
import {PoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolQuotaKeeperV3.sol";
import {GaugeV3} from "@gearbox-protocol/core-v3/contracts/pool/GaugeV3.sol";
import {TumblerV3} from "@gearbox-protocol/core-v3/contracts/pool/TumblerV3.sol";
import {ILPPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/interfaces/ILPPriceFeed.sol";
import {
    IControllerTimelockV3Events,
    IControllerTimelockV3Exceptions,
    Policy
} from "../interfaces/IControllerTimelockV3.sol";
import {IPriceFeedStore} from "../interfaces/IPriceFeedStore.sol";
import "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

// TEST
import "@gearbox-protocol/core-v3/contracts/test/lib/constants.sol";

// MOCKS
import {AddressProviderV3ACLMock} from
    "@gearbox-protocol/core-v3/contracts/test/mocks/core/AddressProviderV3ACLMock.sol";

contract ControllerTimelockV3UnitTest is Test, IControllerTimelockV3Events, IControllerTimelockV3Exceptions {
    AddressProviderV3ACLMock public addressProvider;

    ControllerTimelockV3 public controllerTimelock;

    address admin;
    address vetoAdmin;
    address priceFeedStore;

    function setUp() public {
        admin = makeAddr("ADMIN");
        vetoAdmin = makeAddr("VETO_ADMIN");
        priceFeedStore = makeAddr("PRICE_FEED_STORE");

        vm.prank(CONFIGURATOR);
        addressProvider = new AddressProviderV3ACLMock();
        controllerTimelock = new ControllerTimelockV3(address(addressProvider), vetoAdmin, priceFeedStore);
    }

    function _makeMocks()
        internal
        returns (
            address creditManager,
            address creditFacade,
            address creditConfigurator,
            address pool,
            address poolQuotaKeeper
        )
    {
        creditManager = address(new GeneralMock());
        creditFacade = address(new GeneralMock());
        creditConfigurator = address(new GeneralMock());
        pool = address(new GeneralMock());
        poolQuotaKeeper = address(new GeneralMock());

        vm.mockCall(
            creditManager, abi.encodeWithSelector(ICreditManagerV3.creditFacade.selector), abi.encode(creditFacade)
        );

        vm.mockCall(
            creditManager,
            abi.encodeWithSelector(ICreditManagerV3.creditConfigurator.selector),
            abi.encode(creditConfigurator)
        );

        vm.mockCall(creditManager, abi.encodeWithSelector(ICreditManagerV3.pool.selector), abi.encode(pool));

        vm.mockCall(pool, abi.encodeCall(IPoolV3.poolQuotaKeeper, ()), abi.encode(poolQuotaKeeper));

        vm.label(creditManager, "CREDIT_MANAGER");
        vm.label(creditFacade, "CREDIT_FACADE");
        vm.label(creditConfigurator, "CREDIT_CONFIGURATOR");
        vm.label(pool, "POOL");
        vm.label(poolQuotaKeeper, "PQK");
    }

    ///
    ///
    ///  TESTS
    ///
    ///

    /// @dev U:[CT-1]: configuration functions work correctly
    function test_U_CT_01_configuration_works_correctly() public {
        vm.expectEmit(false, false, false, true);
        emit SetPolicyAdmin("setPriceFeed", admin);

        vm.prank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setPriceFeed", admin);

        vm.expectEmit(false, false, false, true);
        emit SetPolicyDelay("setPriceFeed", uint40(1 days));

        vm.prank(CONFIGURATOR);
        controllerTimelock.setPolicyDelay("setPriceFeed", uint40(1 days));

        (address admin, uint40 delay) = controllerTimelock.policies("setPriceFeed");
        assertEq(admin, admin, "Policy admin is incorrect");
        assertEq(delay, uint40(1 days), "Polict delay is incorrect");

        vm.expectEmit(true, false, false, false);
        emit AddExecutor(FRIEND);

        vm.prank(CONFIGURATOR);
        controllerTimelock.addExecutor(FRIEND);

        assertTrue(controllerTimelock.isExecutor(FRIEND), "Executor is not added");
        assertEq(controllerTimelock.executors().length, 1, "Executor array length is not correct");

        vm.expectEmit(true, false, false, false);
        emit RemoveExecutor(FRIEND);

        vm.prank(CONFIGURATOR);
        controllerTimelock.removeExecutor(FRIEND);

        assertTrue(!controllerTimelock.isExecutor(FRIEND), "Executor is not removed");
        assertEq(controllerTimelock.executors().length, 0, "Executor array length is not correct");
    }

    /// @dev U:[CT-2]: setPriceFeed works correctly
    function test_U_CT_02_setPriceFeed_works_correctly() public {
        address token = makeAddr("TOKEN");
        address priceFeed = makeAddr("PRICE_FEED");
        address priceOracle = makeAddr("PRICE_ORACLE");
        vm.mockCall(priceFeedStore, abi.encodeCall(IPriceFeedStore.getStalenessPeriod, (priceFeed)), abi.encode(4500));
        vm.mockCall(
            priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );
        vm.mockCall(priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, 4500)), "");
        vm.mockCall(
            priceOracle,
            abi.encodeCall(IPriceOracleV3.priceFeedParams, (token)),
            abi.encode(PriceFeedParams(priceFeed, 3000, false, 18))
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setPriceFeed", admin);
        controllerTimelock.setPolicyDelay("setPriceFeed", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setPriceFeed(priceOracle, token, priceFeed);

        // VERIFY THAT THE FUNCTION REVERTS IF THE PRICE FEED IS NOT ALLOWED IN PF STORE
        vm.mockCall(
            priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(false)
        );
        vm.expectRevert(PriceFeedChecksFailedException.selector);
        vm.prank(admin);
        controllerTimelock.setPriceFeed(priceOracle, token, priceFeed);
        vm.mockCall(
            priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(admin, priceOracle, "setPriceFeed(address,address,uint32)", abi.encode(token, priceFeed, 4500))
        );

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            priceOracle,
            "setPriceFeed(address,address,uint32)",
            abi.encode(token, priceFeed, 4500),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setPriceFeed(priceOracle, token, priceFeed);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(
            sanityCheckValue, uint256(keccak256(abi.encode(priceFeed, 3000))), "Sanity check value written incorrectly"
        );

        assertEq(
            sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getCurrentPriceFeedHash, (priceOracle, token))
        );

        vm.expectCall(priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, 4500)));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-3]: setMaxDebtPerBlockMultiplier works correctly
    function test_U_CT_03_setMaxDebtPerBlockMultiplier_works_correctly() public {
        (address creditManager, address creditFacade, address creditConfigurator,,) = _makeMocks();

        vm.mockCall(
            creditFacade, abi.encodeWithSelector(ICreditFacadeV3.maxDebtPerBlockMultiplier.selector), abi.encode(3)
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setMaxDebtPerBlockMultiplier", admin);
        controllerTimelock.setPolicyDelay("setMaxDebtPerBlockMultiplier", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setMaxDebtPerBlockMultiplier(creditManager, 4);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash =
            keccak256(abi.encode(admin, creditConfigurator, "setMaxDebtPerBlockMultiplier(uint8)", abi.encode(4)));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            creditConfigurator,
            "setMaxDebtPerBlockMultiplier(uint8)",
            abi.encode(4),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setMaxDebtPerBlockMultiplier(creditManager, 4);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 3, "Sanity check value written incorrectly");

        assertEq(
            sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getMaxDebtPerBlockMultiplier, (creditManager))
        );

        vm.expectCall(
            creditConfigurator, abi.encodeWithSelector(ICreditConfiguratorV3.setMaxDebtPerBlockMultiplier.selector, 4)
        );

        vm.warp(block.timestamp + 2 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-4]: forbidAdapter works correctly
    function test_U_CT_04_forbidAdapter_works_correctly() public {
        (address creditManager,, address creditConfigurator,,) = _makeMocks();

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("forbidAdapter", admin);
        controllerTimelock.setPolicyDelay("forbidAdapter", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.forbidAdapter(creditManager, DUMB_ADDRESS);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash =
            keccak256(abi.encode(admin, creditConfigurator, "forbidAdapter(address)", abi.encode(DUMB_ADDRESS)));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            creditConfigurator,
            "forbidAdapter(address)",
            abi.encode(DUMB_ADDRESS),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.forbidAdapter(creditManager, DUMB_ADDRESS);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 0, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, "");

        vm.expectCall(
            creditConfigurator, abi.encodeWithSelector(ICreditConfiguratorV3.forbidAdapter.selector, DUMB_ADDRESS)
        );

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-5]: allowToken works correctly
    function test_U_CT_05_allowToken_works_correctly() public {
        (address creditManager,, address creditConfigurator,,) = _makeMocks();

        address token = makeAddr("TOKEN");

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("allowToken", admin);
        controllerTimelock.setPolicyDelay("allowToken", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.allowToken(creditManager, token);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(abi.encode(admin, creditConfigurator, "allowToken(address)", abi.encode(token)));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            creditConfigurator,
            "allowToken(address)",
            abi.encode(token),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.allowToken(creditManager, token);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 0, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, "");

        vm.expectCall(creditConfigurator, abi.encodeWithSelector(ICreditConfiguratorV3.allowToken.selector, token));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-6]: removeEmergencyLiquidator works correctly
    function test_U_CT_06_removeEmergencyLiquidator_works_correctly() public {
        (address creditManager,, address creditConfigurator,,) = _makeMocks();

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("removeEmergencyLiquidator", admin);
        controllerTimelock.setPolicyDelay("removeEmergencyLiquidator", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.removeEmergencyLiquidator(creditManager, DUMB_ADDRESS);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(admin, creditConfigurator, "removeEmergencyLiquidator(address)", abi.encode(DUMB_ADDRESS))
        );

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            creditConfigurator,
            "removeEmergencyLiquidator(address)",
            abi.encode(DUMB_ADDRESS),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.removeEmergencyLiquidator(creditManager, DUMB_ADDRESS);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 0, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, "");

        vm.expectCall(
            creditConfigurator,
            abi.encodeWithSelector(ICreditConfiguratorV3.removeEmergencyLiquidator.selector, DUMB_ADDRESS)
        );

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-7]: setCreditManagerDebtLimit works correctly
    function test_U_CT_07_setCreditManagerDebtLimit_works_correctly() public {
        (address creditManager,,, address pool,) = _makeMocks();

        vm.mockCall(
            pool, abi.encodeWithSelector(IPoolV3.creditManagerDebtLimit.selector, creditManager), abi.encode(1e18)
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setCreditManagerDebtLimit", admin);
        controllerTimelock.setPolicyDelay("setCreditManagerDebtLimit", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setCreditManagerDebtLimit(creditManager, 2e18);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(admin, pool, "setCreditManagerDebtLimit(address,uint256)", abi.encode(creditManager, 2e18))
        );

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            pool,
            "setCreditManagerDebtLimit(address,uint256)",
            abi.encode(creditManager, 2e18),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setCreditManagerDebtLimit(creditManager, 2e18);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 1e18, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getCreditManagerDebtLimit, (creditManager)));

        vm.expectCall(pool, abi.encodeWithSelector(PoolV3.setCreditManagerDebtLimit.selector, creditManager, 2e18));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-8]: setTotalDebtLimit works correctly
    function test_U_CT_08_setTotalDebtLimit_works_correctly() public {
        (address creditManager,,, address pool,) = _makeMocks();

        vm.mockCall(pool, abi.encodeWithSelector(IPoolV3.totalDebtLimit.selector), abi.encode(1e18));

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setTotalDebtLimit", admin);
        controllerTimelock.setPolicyDelay("setTotalDebtLimit", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setTotalDebtLimit(creditManager, 2e18);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(abi.encode(admin, pool, "setTotalDebtLimit(uint256)", abi.encode(2e18)));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash, admin, pool, "setTotalDebtLimit(uint256)", abi.encode(2e18), uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setTotalDebtLimit(pool, 2e18);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 1e18, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getTotalDebtLimit, (pool)));

        vm.expectCall(pool, abi.encodeWithSelector(PoolV3.setTotalDebtLimit.selector, 2e18));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-9]: setTokenLimit works correctly
    function test_U_CT_09_setTokenLimit_works_correctly() public {
        (,,, address pool, address poolQuotaKeeper) = _makeMocks();

        address token = makeAddr("TOKEN");

        vm.mockCall(
            poolQuotaKeeper,
            abi.encodeCall(IPoolQuotaKeeperV3.getTokenQuotaParams, (token)),
            abi.encode(uint16(10), uint192(1e27), uint16(15), uint96(1e17), uint96(1e18), true)
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setTokenLimit", admin);
        controllerTimelock.setPolicyDelay("setTokenLimit", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setTokenLimit(pool, token, 2e18);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(admin, poolQuotaKeeper, "setTokenLimit(address,uint96)", abi.encode(token, uint96(2e18)))
        );

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            poolQuotaKeeper,
            "setTokenLimit(address,uint96)",
            abi.encode(token, uint96(2e18)),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setTokenLimit(pool, token, 2e18);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 1e18, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getTokenLimit, (pool, token)));

        vm.expectCall(poolQuotaKeeper, abi.encodeCall(PoolQuotaKeeperV3.setTokenLimit, (token, 2e18)));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-10]: setTokenQuotaIncreaseFee works correctly
    function test_U_CT_10_setTokenQuotaIncreaseFee_works_correctly() public {
        (,,, address pool, address poolQuotaKeeper) = _makeMocks();

        address token = makeAddr("TOKEN");

        vm.mockCall(
            poolQuotaKeeper,
            abi.encodeCall(IPoolQuotaKeeperV3.getTokenQuotaParams, (token)),
            abi.encode(uint16(10), uint192(1e27), uint16(15), uint96(1e17), uint96(1e18), false)
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setTokenQuotaIncreaseFee", admin);
        controllerTimelock.setPolicyDelay("setTokenQuotaIncreaseFee", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setTokenQuotaIncreaseFee(pool, token, 20);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(
                admin, poolQuotaKeeper, "setTokenQuotaIncreaseFee(address,uint16)", abi.encode(token, uint16(20))
            )
        );

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            poolQuotaKeeper,
            "setTokenQuotaIncreaseFee(address,uint16)",
            abi.encode(token, uint16(20)),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setTokenQuotaIncreaseFee(pool, token, 20);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 15, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getTokenQuotaIncreaseFee, (pool, token)));

        vm.expectCall(poolQuotaKeeper, abi.encodeCall(PoolQuotaKeeperV3.setTokenQuotaIncreaseFee, (token, 20)));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-11]: setMinQuotaRate works correctly
    function test_U_CT_11_setMinQuotaRate_works_correctly() public {
        (,,, address pool, address poolQuotaKeeper) = _makeMocks();

        address gauge = address(new GeneralMock());

        vm.mockCall(poolQuotaKeeper, abi.encodeCall(IPoolQuotaKeeperV3.gauge, ()), abi.encode(gauge));

        address token = makeAddr("TOKEN");

        vm.mockCall(
            gauge,
            abi.encodeCall(IGaugeV3.quotaRateParams, (token)),
            abi.encode(uint16(10), uint16(20), uint96(100), uint96(200))
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setMinQuotaRate", admin);
        controllerTimelock.setPolicyDelay("setMinQuotaRate", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setMinQuotaRate(pool, token, 20);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash =
            keccak256(abi.encode(admin, gauge, "changeQuotaMinRate(address,uint16)", abi.encode(token, uint16(15))));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            gauge,
            "changeQuotaMinRate(address,uint16)",
            abi.encode(token, uint16(15)),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setMinQuotaRate(pool, token, 15);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 10, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getMinQuotaRate, (pool, token)));

        vm.expectCall(gauge, abi.encodeCall(GaugeV3.changeQuotaMinRate, (token, 15)));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-12]: setMaxQuotaRate works correctly
    function test_U_CT_12_setMaxQuotaRate_works_correctly() public {
        (,,, address pool, address poolQuotaKeeper) = _makeMocks();

        address gauge = address(new GeneralMock());

        vm.mockCall(poolQuotaKeeper, abi.encodeCall(IPoolQuotaKeeperV3.gauge, ()), abi.encode(gauge));

        address token = makeAddr("TOKEN");

        vm.mockCall(
            gauge,
            abi.encodeCall(IGaugeV3.quotaRateParams, (token)),
            abi.encode(uint16(10), uint16(20), uint96(100), uint96(200))
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setMaxQuotaRate", admin);
        controllerTimelock.setPolicyDelay("setMaxQuotaRate", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setMaxQuotaRate(pool, token, 20);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash =
            keccak256(abi.encode(admin, gauge, "changeQuotaMaxRate(address,uint16)", abi.encode(token, uint16(25))));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            gauge,
            "changeQuotaMaxRate(address,uint16)",
            abi.encode(token, uint16(25)),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setMaxQuotaRate(pool, token, 25);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 20, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getMaxQuotaRate, (pool, token)));

        vm.expectCall(gauge, abi.encodeCall(GaugeV3.changeQuotaMaxRate, (token, 25)));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-13]: setTumblerQuotaRate works correctly
    function test_U_CT_13_setTumblerQuotaRate_works_correctly() public {
        (,,, address pool, address poolQuotaKeeper) = _makeMocks();

        address tumbler = address(new GeneralMock());

        vm.mockCall(poolQuotaKeeper, abi.encodeCall(IPoolQuotaKeeperV3.gauge, ()), abi.encode(tumbler));

        address token = makeAddr("TOKEN");

        address[] memory tokens = new address[](1);
        tokens[0] = token;

        uint16[] memory rates = new uint16[](1);
        rates[0] = 20;

        vm.mockCall(tumbler, abi.encodeCall(TumblerV3.getRates, (tokens)), abi.encode(rates));

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setTumblerQuotaRate", admin);
        controllerTimelock.setPolicyDelay("setTumblerQuotaRate", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.setTumblerQuotaRate(pool, token, 25);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(abi.encode(admin, tumbler, "setRate(address,uint16)", abi.encode(token, uint16(25))));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(
            txHash,
            admin,
            tumbler,
            "setRate(address,uint16)",
            abi.encode(token, uint16(25)),
            uint40(block.timestamp + 1 days)
        );

        vm.prank(admin);
        controllerTimelock.setTumblerQuotaRate(pool, token, 25);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 20, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, abi.encodeCall(ControllerTimelockV3.getTumblerRate, (pool, token)));

        vm.expectCall(tumbler, abi.encodeCall(TumblerV3.setRate, (token, 25)));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-14]: updateTumblerRates works correctly
    function test_U_CT_14_updateTumblerRates_works_correctly() public {
        (,,, address pool, address poolQuotaKeeper) = _makeMocks();

        address tumbler = address(new GeneralMock());

        vm.mockCall(poolQuotaKeeper, abi.encodeCall(IPoolQuotaKeeperV3.gauge, ()), abi.encode(tumbler));

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("updateTumblerRates", admin);
        controllerTimelock.setPolicyDelay("updateTumblerRates", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS ONLY CALLABLE BY ADMIN
        vm.expectRevert(CallerNotPolicyAdminException.selector);
        vm.prank(USER);
        controllerTimelock.updateTumblerRates(pool);

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(abi.encode(admin, tumbler, "updateRates()", ""));

        vm.expectEmit(true, false, false, true);
        emit QueueTransaction(txHash, admin, tumbler, "updateRates()", "", uint40(block.timestamp + 1 days));

        vm.prank(admin);
        controllerTimelock.updateTumblerRates(pool);

        (,,,,,, uint256 sanityCheckValue, bytes memory sanityCheckCallData) =
            controllerTimelock.queuedTransactions(txHash);

        assertEq(sanityCheckValue, 0, "Sanity check value written incorrectly");

        assertEq(sanityCheckCallData, "");

        vm.expectCall(tumbler, abi.encodeWithSelector(TumblerV3.updateRates.selector));

        vm.warp(block.timestamp + 1 days);

        vm.prank(admin);
        controllerTimelock.executeTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after execution");
    }

    /// @dev U:[CT-15]: cancelTransaction works correctly
    function test_U_CT_15_cancelTransaction_works_correctly() public {
        address token = makeAddr("TOKEN");
        address priceFeed = makeAddr("PRICE_FEED");
        address priceOracle = makeAddr("PRICE_ORACLE");
        vm.mockCall(priceFeedStore, abi.encodeCall(IPriceFeedStore.getStalenessPeriod, (priceFeed)), abi.encode(4500));
        vm.mockCall(
            priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );
        vm.mockCall(priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, 4500)), "");
        vm.mockCall(
            priceOracle,
            abi.encodeCall(IPriceOracleV3.priceFeedParams, (token)),
            abi.encode(PriceFeedParams(priceFeed, 3000, false, 18))
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setPriceFeed", admin);
        controllerTimelock.setPolicyDelay("setPriceFeed", 1 days);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(admin, priceOracle, "setPriceFeed(address,address,uint32)", abi.encode(token, priceFeed, 4500))
        );

        vm.prank(admin);
        controllerTimelock.setPriceFeed(priceOracle, token, priceFeed);

        vm.warp(block.timestamp + 1 days);

        vm.expectRevert(CallerNotVetoAdminException.selector);
        vm.prank(admin);
        controllerTimelock.cancelTransaction(txHash);

        vm.prank(vetoAdmin);
        controllerTimelock.cancelTransaction(txHash);

        (bool queued,,,,,,,) = controllerTimelock.queuedTransactions(txHash);

        assertTrue(!queued, "Transaction is still queued after cancelling");

        vm.expectRevert(TxNotQueuedException.selector);
        controllerTimelock.executeTransaction(txHash);
    }

    /// @dev U:[CT-16]: executeTransaction works correctly
    function test_U_CT_16_executeTransaction_works_correctly() public {
        address token = makeAddr("TOKEN");
        address priceFeed = makeAddr("PRICE_FEED");
        address priceOracle = makeAddr("PRICE_ORACLE");
        vm.mockCall(priceFeedStore, abi.encodeCall(IPriceFeedStore.getStalenessPeriod, (priceFeed)), abi.encode(4500));
        vm.mockCall(
            priceFeedStore, abi.encodeCall(IPriceFeedStore.isAllowedPriceFeed, (token, priceFeed)), abi.encode(true)
        );
        vm.mockCall(priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, 4500)), "");
        vm.mockCall(
            priceOracle,
            abi.encodeCall(IPriceOracleV3.priceFeedParams, (token)),
            abi.encode(PriceFeedParams(priceFeed, 3000, false, 18))
        );

        vm.startPrank(CONFIGURATOR);
        controllerTimelock.setPolicyAdmin("setPriceFeed", admin);
        controllerTimelock.setPolicyDelay("setPriceFeed", 1 days);
        controllerTimelock.addExecutor(FRIEND);
        vm.stopPrank();

        // VERIFY THAT THE FUNCTION IS QUEUED AND EXECUTED CORRECTLY
        bytes32 txHash = keccak256(
            abi.encode(admin, priceOracle, "setPriceFeed(address,address,uint32)", abi.encode(token, priceFeed, 4500))
        );

        vm.prank(admin);
        controllerTimelock.setPriceFeed(priceOracle, token, priceFeed);

        vm.expectRevert(CallerNotExecutorException.selector);
        vm.prank(USER);
        controllerTimelock.executeTransaction(txHash);

        vm.expectRevert(TxExecutedOutsideTimeWindowException.selector);
        vm.prank(FRIEND);
        controllerTimelock.executeTransaction(txHash);

        vm.warp(block.timestamp + 20 days);

        vm.expectRevert(TxExecutedOutsideTimeWindowException.selector);
        vm.prank(FRIEND);
        controllerTimelock.executeTransaction(txHash);

        vm.warp(block.timestamp - 10 days);

        vm.mockCallRevert(
            priceOracle,
            abi.encodeWithSelector(IPriceOracleV3.setPriceFeed.selector, token, priceFeed, 4500),
            abi.encode("error")
        );

        vm.expectRevert(TxExecutionRevertedException.selector);
        vm.prank(FRIEND);
        controllerTimelock.executeTransaction(txHash);

        vm.clearMockedCalls();

        vm.mockCall(priceOracle, abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, 4500)), "");
        vm.mockCall(
            priceOracle,
            abi.encodeCall(IPriceOracleV3.priceFeedParams, (token)),
            abi.encode(PriceFeedParams(priceFeed, 3600, false, 18))
        );

        vm.expectRevert(ParameterChangedAfterQueuedTxException.selector);
        vm.prank(FRIEND);
        controllerTimelock.executeTransaction(txHash);

        vm.mockCall(
            priceOracle,
            abi.encodeCall(IPriceOracleV3.priceFeedParams, (token)),
            abi.encode(PriceFeedParams(priceFeed, 3000, false, 18))
        );

        vm.expectEmit(true, false, false, false);
        emit ExecuteTransaction(txHash);

        vm.prank(FRIEND);
        controllerTimelock.executeTransaction(txHash);
    }
}