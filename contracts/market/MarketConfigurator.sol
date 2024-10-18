// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPriceOracleV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";
import {IControlledTrait} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IControlledTrait.sol";
import {IPriceFeed, IUpdatablePriceFeed} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IPriceFeed.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {IPoolFactory} from "../interfaces/IPoolFactory.sol";
import "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {PERCENTAGE_FACTOR} from "@gearbox-protocol/core-v3/contracts/libraries/Constants.sol";

import {IACLExt} from "../interfaces/extensions/IACLExt.sol";
import {IContractsRegisterExt} from "../interfaces/extensions/IContractsRegisterExt.sol";
import {IRateKeeperExt} from "../interfaces/extensions/IRateKeeperExt.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";
import {IContractsFactory} from "../interfaces/IContractsFactory.sol";
import {IRateKeeperFactory} from "../interfaces/IRateKeeperFactory.sol";
import {IMarketConfigurator, CreateMarketParams} from "../interfaces/IMarketConfigurator.sol";
import {IPriceFeedStore} from "../interfaces/IPriceFeedStore.sol";

import {AP_MARKET_CONFIGURATOR, AP_PRICE_FEED_STORE} from "../libraries/ContractLiterals.sol";
import {NestedPriceFeeds} from "../libraries/NestedPriceFeeds.sol";
import {Call} from "../interfaces/Types.sol";

// TODO:
// - zappers management
// - degen NFT management
// - migration to new market configurator
// - rescue
// - onInstall / onUninstall callbacks

/// @title Market configurator
contract MarketConfigurator is Ownable2Step, IMarketConfigurator {
    using Address for address;
    using SafeERC20 for IERC20;
    using NestedPriceFeeds for IPriceFeed;
    using EnumerableSet for EnumerableSet.AddressSet;

    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR;

    address public immutable override configuratorFactory;
    address public immutable override addressProvider;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    address public override contractsFactory;
    address public override priceFeedStore;

    mapping(address => address) public poolToPoolFactories;
    mapping(address => address) public creditManagerToCreditFactories;

    // PriceOracle 1:1
    mapping(address pool => address) public override priceOracles;

    // LossLiquidator 1:1 for market policy
    mapping(address pool => address) public override lossLiquidators;

    // Can it fit for multiple versions
    address public override controller;
    EnumerableSet.AddressSet internal _emergencyLiquidators;

    // ------ //
    // ERRORS //
    // ------ //

    // Thrown if an unauthorized price feed is used for a token
    error PriceFeedNotAllowedException(address token, address priceFeed);

    // Thrown if an adapter is not properly initialized for a credit manager
    error AdapterNotInitializedException(address creditManager, address targetContract);

    // Thrown if a loss liquidator is not initialized for a pool
    error LossLiquidatorNotInitializedException(address pool);

    // Thrown if an unauthorized configuration call is made
    error ForbiddenConfigurationCallException(address target, bytes4 selector);

    // Thrown if attempting to set a new version lower than the current one
    error NewVersionBelowCurrentException();

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    /// @notice Initializes the MarketConfigurator with the provided parameters.
    /// @param riskCurator_ The address of the risk curator.
    /// @param addressProvider_ The address of the address provider.
    /// @param acl_ The address of the access control list.
    /// @param contractsRegister_ The address of the contracts register.
    /// @param treasury_ The address of the treasury.
    /// @param controllerParams The parameters for deploying the controller.
    constructor(
        address riskCurator_,
        address addressProvider_,
        address acl_,
        address contractsRegister_,
        address treasury_,
        bytes memory controllerParams
    ) {
        _transferOwnership(riskCurator_);
        addressProvider = addressProvider_;
        acl = acl_;
        contractsRegister = contractsRegister_;
        treasury = treasury_;

        priceFeedStore = _getLatestContract(AP_PRICE_FEED_STORE);

        controller = _deployController(controllerParams);
    }

    // --------------- //
    // POOL MANAGEMENT //
    // --------------- //

    /**
     * @notice Creates a new market with the specified parameters
     * @param params A struct containing all the necessary parameters for market creation:
     *        - underlying: The address of the underlying asset for the market
     *        - symbol: The symbol for the market
     *        - name: The name for the market
     *        - poolParams: Encoded parameters for pool creation
     *        - underlyingPriceFeed: The address of the price feed for the underlying asset
     *        - priceOracleParams: Encoded parameters for price oracle creation
     *        - irmPostFix: The postfix for the Interest Rate Model
     *        - irmParams: Encoded parameters for Interest Rate Model creation
     *        - rateKeeperPosfix: The postfix for the Rate Keeper
     *        - rateKeeperParams: Encoded parameters for Rate Keeper creation
     * @return The address of the newly created pool
     */
    function createMarket(CreateMarketParams calldata params) external onlyOwner returns (address) {
        // Deploy IRM
        (address irm) = _deployInterestRateModel(params.irmPostFix, params.irmParams);

        // Deploy Pool Factory

        // QUESTION: deploy in factory or return call to bytecode resository and execute in _executeHook
        (address pool, Call[] memory onInstallOps) = IPoolFactory(latestPoolFactory).deployPool(
            acl, contractsRegister, params.underlying, treasury, irm, params.poolParams
        );

        // IDEA: marketConfigutor.accessList[contract] = factory;
        _executeHook(onInstallOps);

        // QUESTION: move all contracts to new contracts register?
        poolToPoolFactories[pool] = latestPoolFactory;

        IContractsRegisterExt(contractsRegister).addPool(pool);

        //  IContractsRegisterExt(contractsRegister).onCreditMarket(pool);

        // RateKeeperFactory (RK_)
        address rateKeeper = IRateKeeperFactory(latestRateKeeperFactory).deployRateKeeper(
            pool, params.rateKeeperType, params.rateKeeperParams
        );

        _executeHook(IContractRegister(contractsRegister).onUpdateRateKeeper(pool, rateKeeper));
        _executeHook(IPoolFactory(latestPoolFactory).onUpdateRateKeeper(pool, rateKeeper));

        // onInstall()
        _gearStakring_onInstall(pool, rateKeeper);

        // PriceOracleFactory
        address priceOracle = _deployPriceOracle(params.priceOracleParams);

        // keep price oracle in contract register?
        priceOracles[pool] = priceOracle;

        // check that underlying price is non-zero
        // if (_getPrice(params.underlyingPriceFeed) == 0) revert IncorrectPriceException();

        _setPriceFeed(priceOracle, params.underlying, params.underlyingPriceFeed, false);

        // address controller_ = controller;
        // _setController(irm, controller_);
        // _setController(pool, controller_);
        // _setController(quotaKeeper, controller_);
        // _setController(rateKeeper, controller_);
        // _setController(priceOracle, controller_);

        return pool;
    }

    // @global
    function removeMarket(address pool) external onlyOwner {
        _ensureRegisteredPool(pool);

        // remove rate keeper from gearstakring
        _gearStaking_onRemove(_rateKeeper(_quotaKeeper(pool)));

        _executeHook(IPoolFactory(poolToPoolFactories[pool]).onRemoveMarket(pool));

        // onUninstallPriceOracles
        priceOracles[pool] = address(0);

        // ??
        lossLiquidators[pool] = address(0);
        IContractsRegisterExt(contractsRegister).removePool(pool);
    }

    //
    // @market
    //

    // @market
    function addToken(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        _setPriceFeed(priceOracles[pool], token, priceFeed, false);

        _executeHook(IPoolFactory(poolToPoolFactories[pool]).onAddToken(pool, token, priceFeed));
        _executeHook(IRateKeeperFactory(poolToRrateKeeperFactory[pool]).onAddToken(pool, token, priceFeed));
    }

    // credit factory depends on credit configurator

    // @market
    function createCreditSuite(address pool, bytes calldata encodedParams)
        external
        onlyOwner
        returns (address creditManager)
    {
        _ensureRegisteredPool(pool);

        creditManager = ICreditFactory(lastCreditFactory).createCreditSuite(pool, encodedParams);

        // assert priceOracle is correct
        if (ICreditManagerV3(creditManager).priceOracle() != priceOracle[pool]) {
            revert ContractIncorrectlyConfiguredException(creditManager);
        }

        // asset pool is correct
        if (ICreditManagerV3(creditManager).pool() != pool) {
            revert ContractIncorrectlyConfiguredException(creditManager);
        }

        creditManagerToCreditFactories[creditManager] = lastCreditFactory;

        IContractsRegisterExt(contractsRegister).addCreditManager(creditManager);
        // _setCreditManagerDebtLimit(pool, creditManager, params.debtLimit);

        _executeHook(IPoolFactory(poolFactories[pool]).onAddCreditManager(creditManager));
        // Via pool factory
        // IPoolQuotaKeeperV3(_quotaKeeper(pool)).addCreditManager(creditManager);
    }

    function removeCreditSuite(address creditManager) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        // onCreditSuite hook
        IPoolFactory(poolToPoolFactories[pool]).onRemoveCreditManager(creditManager);
        IContractsRegisterExt(contractsRegister).removeCreditManager(creditManager);
    }

    function configureCreditSuite(address creditManager, bytes calldata data) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        (address target, bytes memory callData) = creditManagerToCreditFactories[creditManager].verify(data);
        target.functionCall(callData);
    }

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function updateInterestRateModel(address pool, bytes32 type_, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address irm = IInterestRateModelFactory(latestInterestRateModel).deployModel(type_, params);

        // who should be on hook?
        _executeHook(IPoolFactory(poolToPoolFactories[pool]).onUpdateInterestModel(pool, irm));

        _setController(irm, controller);
    }

    function configureInterestRateModel(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        address irm = _interestRateModel(pool);
        _safeControllerFunctionCall(irm, data);
    }

    function _deployInterestRateModel(bytes32 type_, bytes memory params) internal returns (address) {
        return IContractsFactory(contractsFactory).deployInterestRateModel(acl, type_, params);
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    //
    function updatePriceOracle(address pool, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address priceOracle = _deployPriceOracle(params);
        address prevPriceOracle = priceOracles[pool];
        priceOracles[pool] = priceOracle;
        poolToPriceFactory[pool] = lastPriceOracleFactory;

        IPriceFactory(lastPriceOracleFactory).onUpdatePriceOracle(pool, priceOracle, prevPriceOracle);

        // Executes onPriceOracleUpdate on all credit managers of a pool
        _callPoolCreditManagerHooks(pool, abi.encodeCall(ICreditHooks.onPriceOracleUpdate, priceOracle));

        _setController(priceOracle, controller);
    }

    // @market
    function setPriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        // set price feed
        executeHook(IPriceOracleFactory(poolToPriceOracleFactory[pool]).onSetPriceFeed(priceOracle, token, priceFeed));

        // execute pool hook
        _executeHook(IPoolFactory(poolToPoolFactories[pool]).onSetPriceFeed(pool, token, priceFeed));

        // QUESTION: other hooks?
    }

    // @market
    function setReservePriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        _setPriceFeed(priceOracles[pool], token, priceFeed, true);
    }

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    // @market
    function updateRateKeeper(address pool, bytes32 type_, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        // address quotaKeeper = _quotaKeeper(pool);
        // address currentRateKeeper = _rateKeeper(quotaKeeper);
        // _gearStaking_onRemove(currentRateKeeper);

        // address rateKeeper = _deployRateKeeper(pool, type_, params);
        // address[] memory tokens = IPoolQuotaKeeperV3(quotaKeeper).quotedTokens();
        // uint256 numTokens = tokens.length;
        // for (uint256 i; i < numTokens; ++i) {
        //     _addToken(rateKeeper, tokens[i], type_);
        // }
        // _gearStakring_onInstall(quotaKeeper, rateKeeper);

        // _setController(rateKeeper, controller);
    }

    function configureRateKeeper(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);

        // address rateKeeper = _rateKeeper(_quotaKeeper(pool));

        // bytes4 selector = bytes4(data);
        // if (selector == IControlledTrait.setController.selector || selector == _getAddTokenSelector(rateKeeper)) {
        //     revert ForbiddenConfigurationCallException(rateKeeper, selector);
        // }
        // rateKeeper.functionCall(data);
    }

    function _deployRateKeeper(address pool, bytes32 type_, bytes memory params) internal returns (address) {
        return IContractsFactory(contractsFactory).deployRateKeeper(pool, type_, params);
    }

    // function _addToken(address rateKeeper, address token, bytes32 type_) internal {
    //     if (type_ == "RK_GAUGE") {
    //         IGaugeV3(rateKeeper).addQuotaToken({token: token, minRate: 1, maxRate: 1});
    //     } else if (type_ == "RK_TUMBLER") {
    //         ITumblerV3(rateKeeper).addToken({token: token, rate: 1});
    //     } else {
    //         IRateKeeperExt(rateKeeper).addToken(token);
    //     }
    // }

    // function _getAddTokenSelector(address rateKeeper) internal view returns (bytes4) {
    //     bytes32 type_ = _getRateKeeperType(rateKeeper);
    //     if (type_ == "RK_GAUGE") return IGaugeV3.addQuotaToken.selector;
    //     if (type_ == "RK_TUMBLER") return ITumblerV3.addToken.selector;
    //     return IRateKeeperExt.addToken.selector;
    // }

    function _gearStakring_onInstall(address rateKeeper) internal {
        if (_isVotingContract(rateKeeper)) {
            _setVotingContractStatus(rateKeeper, VotingContractStatus.ALLOWED);
        }
    }

    function _gearStaking_onRemove(address rateKeeper) internal {
        if (_isVotingContract(rateKeeper)) {
            _setVotingContractStatus(rateKeeper, VotingContractStatus.UNVOTE_ONLY);
            try IGaugeV3(rateKeeper).setFrozenEpoch(true) {} catch {}
        }
    }

    // Could it be IRM for example?

    function _isVotingContract(address rateKeeper) internal view returns (bool) {
        try IVotingContract(rateKeeper).voter() returns (address) {
            return true;
        } catch {
            return false;
        }
    }

    //
    // @pool via Factory
    //

    // // @pool
    // function setTotalDebtLimit(address pool, uint256 newLimit) external onlyOwner {
    //     _ensureRegisteredPool(pool);

    //     _setTotalDebtLimit(pool, newLimit);
    // }

    // // @pool
    // function setWithdrawFee(address pool, uint256 newWithdrawFee) external onlyOwner {
    //     _ensureRegisteredPool(pool);

    //     _setWithdrawFee(pool, newWithdrawFee);
    // }

    // // @pool
    // function setTokenLimit(address pool, address token, uint96 limit) external onlyOwner {
    //     _ensureRegisteredPool(pool);

    //     IPoolQuotaKeeperV3(_quotaKeeper(pool)).setTokenLimit(token, limit);
    // }

    // // @pool
    // function setTokenQuotaIncreaseFee(address pool, address token, uint16 fee) external onlyOwner {
    //     _ensureRegisteredPool(pool);

    //     IPoolQuotaKeeperV3(_quotaKeeper(pool)).setTokenQuotaIncreaseFee(token, fee);
    // }

    // function _setTotalDebtLimit(address pool, uint256 newLimit) internal {
    //     IPoolV3(pool).setTotalDebtLimit(newLimit);
    // }

    // function _setWithdrawFee(address pool, uint256 newWithdrawFee) internal {
    //     IPoolV3(pool).setWithdrawFee(newWithdrawFee);
    // }

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    struct CreditSuiteParams {
        uint256 debtLimit;
        uint128 minDebt;
        uint128 maxDebt;
        uint16 feeLiquidation;
        uint16 liquidationPremium;
        uint16 feeLiquidationExpired;
        uint16 liquidationPremiumExpired;
        bytes managerParams;
        bytes configuratorParams;
        bytes facadeParams;
    }

    // ------------------ //
    // ADAPTER MANAGEMENT //
    // ------------------ //

    // // @credit
    // function allowAdapter(address creditManager, address targetContract, bytes calldata params) external onlyOwner {
    //     _ensureRegisteredCreditManager(creditManager);

    //     address adapter = IContractsFactory(contractsFactory).deployAdapter(creditManager, targetContract, params);
    //     ICreditConfiguratorV3(_creditConfigurator(creditManager)).allowAdapter(adapter);
    // }

    // function forbidAdapter(address creditManager, address targetContract) external onlyOwner {
    //     _ensureRegisteredCreditManager(creditManager);

    //     address adapter = _getAdapterOrRevert(creditManager, targetContract);
    //     ICreditConfiguratorV3(_creditConfigurator(creditManager)).forbidAdapter(adapter);
    // }

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function addPausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).addPausableAdmin(admin);
    }

    function addUnpausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).addUnpausableAdmin(admin);
    }

    function removePausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).removePausableAdmin(admin);
    }

    function removeUnpausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).removeUnpausableAdmin(admin);
    }

    // QUESTION: rewrite using role model?
    function addEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.add(liquidator)) return;
        _callCreditManagerHooks(abi.encodeCall(ICreditHooks.onAddEmergencyLiquidator, liquidator));
        // address[] memory creditManagers = _creditManagers();
        // uint256 numManagers = creditManagers.length;
        // for (uint256 i; i < numManagers; ++i) {
        //     _addEmergencyLiquidator(_creditConfigurator(creditManagers[i]), liquidator);
        // }
    }

    function _applyForAllCreditManagers(address pool, bytes calldata callData) internal {
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            (_creditConfigurator(creditManagers[i])).functionCall(callData);
        }
    }

    function removeEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.remove(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            ICreditConfiguratorV3(_creditConfigurator(creditManagers[i])).removeEmergencyLiquidator(liquidator);
        }
    }

    function updateLossLiquidator(address pool, bytes32 type_, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address lossLiquidator = IContractsFactory(contractsFactory).deployLossLiquidator(pool, type_, params);

        // @update all credit managers
        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            // TODO: Rewrite for factory call(?)
            // _setLossLiquidator(_creditConfigurator(creditManagers[i]), lossLiquidator);
        }

        lossLiquidators[pool] = lossLiquidator;

        _setController(lossLiquidator, controller);
    }

    function configureLossLiquidator(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);

        address lossLiquidator = lossLiquidators[pool];
        if (lossLiquidator == address(0)) revert LossLiquidatorNotInitializedException(pool);

        _safeControllerFunctionCall(lossLiquidator, data);
    }

    // @global
    function updateController(bytes calldata params) external onlyOwner {
        // address controller_ = _deployController(params);

        // address[] memory pools = _pools();
        // uint256 numPools = pools.length;
        // for (uint256 i; i < numPools; ++i) {
        //     address pool = pools[i];
        //     address quotaKeeper = _quotaKeeper(pool);

        //     _setController(_interestRateModel(pool), controller_);
        //     _setController(pool, controller_);
        //     _setController(quotaKeeper, controller_);
        //     _setController(_rateKeeper(quotaKeeper), controller_);
        //     _setController(priceOracles[pool], controller_);

        //     address lossLiquidator = lossLiquidators[pool];
        //     if (lossLiquidator != address(0)) _setController(lossLiquidator, controller_);
        // }

        // address[] memory creditManagers = _creditManagers();
        // uint256 numManagers = creditManagers.length;
        // for (uint256 i; i < numManagers; ++i) {
        //     _setController(_creditConfigurator(creditManagers[i]), controller_);
        // }

        // controller = controller_;
    }

    // function configureController(bytes calldata data) external onlyOwner {
    //     controller.functionCall(data);
    // }

    // function _addEmergencyLiquidator(address creditConfigurator, address liquidator) internal {
    //     ICreditConfiguratorV3(creditConfigurator).addEmergencyLiquidator(liquidator);
    // }

    // function _setLossLiquidator(address creditConfigurator, address lossLiquidator) internal {
    //     ICreditConfiguratorV3(creditConfigurator).setLossLiquidator(lossLiquidator);
    // }

    // function _deployController(bytes memory params) internal returns (address) {
    //     return IContractsFactory(contractsFactory).deployController(acl, params);
    // }

    // function _setController(address contract_, address controller_) internal {
    //     try IControlledTrait(contract_).setController(controller_) {} catch {}
    // }

    // ------------- //
    // MISCELLANEOUS //
    // ------------- //

    function upgradePriceFeedStore(uint256 newVersion) external onlyOwner {
        priceFeedStore = _upgradeContract(priceFeedStore, AP_PRICE_FEED_STORE, newVersion);
    }

    function _upgradeContract(address contract_, bytes32 type_, uint256 newVersion) internal view returns (address) {
        if (newVersion <= IVersion(contract_).version()) revert NewVersionBelowCurrentException();
        return _getContract(type_, newVersion);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    /// @dev Executes hooks on all connected active credit managers
    function _callCreditManagerHooks(bytes calldata callData) internal {
        _executeCreditManagersHooks(_creditManagers(), callData);
    }
    /// @dev Executes hooks on all connected active credit managers of a given pool

    function _callPoolCreditManagerHooks(address pool, bytes calldata callData) internal {
        _executeCreditManagersHooks(_creditManagersByPool(pool), callData);
    }

    function _executeCreditManagersHooks(address[] memory creditManagers, bytes calldata callData) internal {
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            _executeHook((creditManagerToCreditFactories[creditManagers[i]]).functionCall(callData));
        }
    }

    ///
    ///
    //
    function _safeControllerFunctionCall(address targetContract, bytes calldata data) internal {
        bytes4 selector = bytes4(data);
        if (selector == IControlledTrait.setController.selector) {
            revert ForbiddenConfigurationCallException(targetContract, selector);
        }
        targetContract.functionCall(data);
    }

    function _getContract(bytes32 type_, uint256 version_) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(type_, version_);
    }

    function _getLatestContract(bytes32 type_) internal view returns (address) {
        return IAddressProvider(addressProvider).getLatestAddressOrRevert(type_);
    }

    function _ensureRegisteredPool(address pool) internal view {
        if (!IContractsRegisterExt(contractsRegister).isPool(pool)) {
            revert RegisteredPoolOnlyException();
        }
    }

    function _ensureRegisteredCreditManager(address creditManager) internal view {
        if (!IContractsRegisterExt(contractsRegister).isCreditManager(creditManager)) {
            revert RegisteredCreditManagerOnlyException();
        }
    }

    function _pools() internal view returns (address[] memory) {
        return IContractsRegisterExt(contractsRegister).getPools();
    }

    function _creditManagers() internal view returns (address[] memory) {
        return IContractsRegisterExt(contractsRegister).getCreditManagers();
    }

    // Why is not taken from pool directly
    function _creditManagers(address pool) internal view returns (address[] memory creditManagers) {
        address[] memory allCreditManagers = _creditManagers();
        uint256 totalManagers = allCreditManagers.length;
        creditManagers = new address[](totalManagers);
        uint256 numManagers;
        for (uint256 i; i < totalManagers; ++i) {
            if (_pool(allCreditManagers[i]) == pool) {
                creditManagers[numManagers++] = allCreditManagers[i];
            }
        }
        assembly {
            mstore(creditManagers, numManagers)
        }
    }

    function _interestRateModel(address pool) internal view returns (address) {
        return IPoolV3(pool).interestRateModel();
    }

    function _rateKeeper(address quotaKeeper) internal view returns (address) {
        return IPoolQuotaKeeperV3(quotaKeeper).gauge();
    }

    // function _quota(address pool, address token) internal view returns (uint96 quota) {
    //     (,,, quota,,) = IPoolQuotaKeeperV3(_quotaKeeper(pool)).getTokenQuotaParams(token);
    // }

    // function _quotaKeeper(address pool) internal view returns (address) {
    //     return IPoolV3(pool).poolQuotaKeeper();
    // }

    function _pool(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).pool();
    }

    function _creditConfigurator(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).creditConfigurator();
    }

    //
    function _executeHook(Call[] memory calls) internal {
        uint256 len = calls.length;
        for (uint256 i; i < len; ++i) {
            address target = calls[i].target;
            bytes memory callData = calls[i].callData;

            // TODO: add control that factory could execute only related contracts
            (target).functionCall(callData);
        }
    }

    // Global
    // @global
    function _setVotingContractStatus(address votingContract, VotingContractStatus status) internal {
        IMarketConfiguratorFactory(configuratorFactory).setVotingContractStatus(votingContract, status);
    }

    // QUESTION: switch to role model?
    function emergencyLiquidators() external view override returns (address[] memory) {
        return _emergencyLiquidators.values();
    }
}
