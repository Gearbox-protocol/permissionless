// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPriceOracleV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";

import {IControlledTrait} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IControlledTrait.sol";

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {IPoolFactory} from "../interfaces/IPoolFactory.sol";
import "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {PERCENTAGE_FACTOR} from "@gearbox-protocol/core-v3/contracts/libraries/Constants.sol";

import {IACLExt} from "../interfaces/extensions/IACLExt.sol";
import {IContractsRegisterExt} from "../interfaces/extensions/IContractsRegisterExt.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";
import {IContractsFactory} from "../interfaces/IContractsFactory.sol";
import {IRateKeeperFactory} from "../interfaces/IRateKeeperFactory.sol";
import {IMarketConfigurator, CreateMarketParams} from "../interfaces/IMarketConfigurator.sol";
import {IInterestRateModelFactory} from "../interfaces/IInterestRateModelFactory.sol";
import {IPriceOracleFactory} from "../interfaces/IPriceOracleFactory.sol";
import {ICreditFactory} from "../interfaces/ICreditFactory.sol";

import {AP_MARKET_CONFIGURATOR, AP_PRICE_FEED_STORE} from "../libraries/ContractLiterals.sol";

import {Call, DeployResult} from "../interfaces/Types.sol";
import {IConfigurableFactory} from "../interfaces/IConfigurableFactory.sol";

import {ICreditHooks} from "../interfaces/ICreditHooks.sol";
import {IHook, HookCheck, HookExecutor} from "../libraries/Hook.sol";

// TODO:
// - zappers management
// - degen NFT management
// - migration to new market configurator
// - rescue
// - onInstall / onUninstall callbacks

/// @title Market configurator
contract MarketConfigurator is Ownable2Step, IMarketConfigurator {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;
    using HookExecutor for IHook;

    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR;

    address public immutable override configuratorFactory;
    address public immutable override addressProvider;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    // TODO: move all things below to ContractsRegister
    // address public override contractsFactory;
    address public override priceFeedStore;

    // mapping(address => address) public poolToPoolFactories;
    // mapping(address => address) public creditManagerToCreditFactories;

    // // PriceOracle 1:1
    mapping(address pool => address) public override priceOracles;

    // // LossLiquidator 1:1 for market policy
    mapping(address pool => address) public lossLiquidators;

    address latestInterestRateModelFactory;
    address latestPoolFactory;
    address latestRateKeeperFactory;
    address latestPriceOracleFactory;
    address latestCreditFactory;

    address gearStakingFactory;

    // Can it fit for multiple versions
    address public controller;
    EnumerableSet.AddressSet internal _emergencyLiquidators;

    // Access list is additional protection measure to restrict contracts
    // which could be called via cooks.
    mapping(address => address) public accessList;

    // ------ //
    // ERRORS //
    // ------ //

    // Thrown if an adapter is not properly initialized for a credit manager
    error AdapterNotInitializedException(address creditManager, address targetContract);

    // Thrown if a loss liquidator is not initialized for a pool
    error LossLiquidatorNotInitializedException(address pool);

    // Thrown if an unauthorized configuration call is made
    error ForbiddenConfigurationCallException(address target, bytes4 selector);

    // Thrown if attempting to set a new version lower than the current one
    error NewVersionBelowCurrentException();

    // Thrown if hook attempting to call a contract which is node in accessList
    error ContractNotAssignedToFactoryException(address);

    // Thrown if factory attempting to overwrite exsting addess in accessList
    error ContractAlreadyInAccessListException(address);

    error ContractIncorrectlyConfiguredException(address);

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
     */
    function createMarket(CreateMarketParams calldata params) external onlyOwner returns (address pool) {
        pool = _deployPool(params.underlying, params.name, params.symbol);
        address priceOracle = _deployPriceOracle(params.priceOracleParams);
        _executeHook(IHook(contractsRegister).onCreateMarket(pool, priceOracle));

        _setPriceFeed(pool, params.underlying, params.underlyingPriceFeed);
        _updateInterestRateModel(pool, params.irmPostFix, params.irmParams);
        _updateRateKeeper(pool, params.rateKeeperPosfix, params.rateKeeperParams);
    }

    /**
     * @notice Shutdown a market from the protocol
     * @param pool The address of the pool to remove
     * @dev This function can only be called by the owner
     *      It removes the rate keeper, updates the pool factory,
     *      and removes the market from the contracts register
     */
    function shutdownMarket(address pool) external onlyOwner {
        _ensureRegisteredPool(pool);

        // remove rate keeper from gearstakring
        // QUESTION: should we move it to pool factory?

        // TODO: compute rateKeeper?
        // _executeHook(IHook(gearStakingFactory).onRemoveRateKeeper(pool, rateKeeper));
        _executeHook(IHook(_getPoolFactory(pool)).onShutdownMarket(pool));

        // should be implemented in ContractsRegister
        // priceOracles[pool] = address(0);
        // lossLiquidators[pool] = address(0);
        _executeHook(IHook(contractsRegister).onShutdownMarket(pool));
    }

    function configurePool(address pool, bytes calldata callData) external onlyOwner {
        _ensureRegisteredPool(pool);
        _configureFactory(_getPoolFactory(pool), pool, callData);
    }

    /**
     * @notice Adds a new token to the market
     * @param pool The address of the pool which represents market
     * @param token The address of the token to add
     * @param priceFeed The address of the price feed for the token
     * @dev This function can only be called by the owner
     *      It sets up the price feed for the token and updates the pool factory and rate keeper
     */
    function addToken(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        _executeHook(IHook(_getPriceOracleFactory(pool)).onSetPriceFeed(pool, token, priceFeed));
        _executeHook(IHook(_getPoolFactory(pool)).onAddToken(pool, token, priceFeed));
        _executeHook(IHook(_getRateKeeperFactory(pool)).onAddToken(pool, token, priceFeed));
    }

    // @market
    function createCreditSuite(address pool, bytes calldata encodedParams)
        external
        onlyOwner
        returns (address creditManager)
    {
        _ensureRegisteredPool(pool);

        DeployResult memory deployResult = ICreditFactory(latestCreditFactory).createCreditSuite(pool, encodedParams);
        creditManager = deployResult.newContract;

        _executeOnDeploy(latestCreditFactory, deployResult);

        // Validation. Better to move it into contracts register
        // assert priceOracle is correct
        if (
            ICreditManagerV3(creditManager).priceOracle()
                != IContractsRegisterExt(contractsRegister).getPriceOracle(pool)
        ) {
            revert ContractIncorrectlyConfiguredException(creditManager);
        }

        // asset pool is correct
        if (ICreditManagerV3(creditManager).pool() != pool) {
            revert ContractIncorrectlyConfiguredException(creditManager);
        }

        _setCreditManagerFactory(creditManager, latestCreditFactory);

        _executeHook(IHook(contractsRegister).onAddCreditManager(pool, creditManager));
        _executeHook(IHook(_getPoolFactory(pool)).onAddCreditManager(pool, creditManager));
    }

    function removeCreditSuite(address creditManager) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address pool = ICreditManagerV3(creditManager).pool();

        // onCreditSuite hook
        _executeHook(IHook(_getCreditManagerFactory(creditManager)).onRemoveCreditManager(pool, creditManager));
        _executeHook(IHook(_getPoolFactory(pool)).onRemoveCreditManager(pool, creditManager));
        _executeHook(IHook(contractsRegister).onRemoveCreditManager(pool, creditManager));
    }

    function configureCreditSuite(address creditManager, bytes calldata data) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);
        _configureFactory(_getCreditManagerFactory(creditManager), creditManager, data);
    }

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function updateInterestRateModel(address pool, bytes32 postfix, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);
        _updateInterestRateModel(pool, postfix, params);
    }

    function _updateInterestRateModel(address pool, bytes32 postfix, bytes calldata params) internal {
        address irm = _deployInterestRateModel(postfix, params);
        _executeHook(IHook(_getPoolFactory(pool)).onUpdateInterestModel(pool, irm));
        // which hooks should be adde?
    }

    function configureInterestRateModel(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        address irm = _interestRateModel(pool);
        _configureFactory(_getInterestRateModelFactory(irm), irm, data);
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    //
    function updatePriceOracle(address pool, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address priceOracle = _deployPriceOracle(params);
        address prevPriceOracle = _getPriceOracleFactory(pool);

        _setPriceOracleFactory(pool, latestPriceOracleFactory);

        _executeHook(IHook(latestPriceOracleFactory).onUpdatePriceOracle(pool, priceOracle, prevPriceOracle));

        address[] memory creditManagers = _creditManagersByPool(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                IHook(_getCreditManagerFactory(creditManager)).onUpdatePriceOracle(
                    creditManager, priceOracle, prevPriceOracle
                )
            );
        }
    }

    // @market
    function setPriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);
        _setPriceFeed(pool, token, priceFeed);
    }

    function _setPriceFeed(address pool, address token, address priceFeed) internal {
        // set price feed
        _executeHook(IHook(_getPriceOracleFactory(pool)).onSetPriceFeed(pool, token, priceFeed));
        _executeHook(IHook(_getPoolFactory(pool)).onSetPriceFeed(pool, token, priceFeed));
        // QUESTION: other hooks?
    }

    // @market
    function setReservePriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        // set price feed
        _executeHook(IHook(_getPriceOracleFactory(pool)).onSetReservePriceFeed(pool, token, priceFeed));
        _executeHook(IHook(_getPoolFactory(pool)).onSetReservePriceFeed(pool, token, priceFeed));
    }

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    function updateRateKeeper(address pool, bytes32 postfix, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);
        // TODO: check if rate keeper is already set
        // then execute onRemoveRateKeeper hook
        _updateRateKeeper(pool, postfix, params);
    }

    function _updateRateKeeper(address pool, bytes32 postfix, bytes calldata params) internal {
        address rateKeeper = _deployRateKeeper(pool, postfix, params);

        _executeHook(IHook(contractsRegister).onUpdateRateKeeper(pool, rateKeeper));
        _executeHook(IHook(_getPoolFactory(pool)).onUpdateRateKeeper(pool, rateKeeper));
        _executeHook(IHook(gearStakingFactory).onUpdateRateKeeper(pool, rateKeeper));
    }

    function configureRateKeeper(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        address rateKeeper = _rateKeeper(pool);
        _configureFactory(_getRateKeeperFactory(rateKeeper), rateKeeper, data);
    }

    //
    // DEPLOYMENTS
    //
    function _deployPool(address underlying, string memory name, string memory symbol)
        internal
        returns (address pool)
    {
        DeployResult memory deployResult = IPoolFactory(latestPoolFactory).deployPool(underlying, name, symbol);

        pool = deployResult.newContract;

        _executeOnDeploy(latestPoolFactory, deployResult);
        _setPoolFactory(pool, latestPoolFactory);
    }

    function _deployInterestRateModel(bytes32 postfix, bytes memory params) internal returns (address model) {
        DeployResult memory deployResult =
            IInterestRateModelFactory(latestInterestRateModelFactory).deployInterestRateModel(postfix, params);

        model = deployResult.newContract;

        _executeOnDeploy(latestInterestRateModelFactory, deployResult);
        _setInterestRateModelFactory(model, latestInterestRateModelFactory);
    }

    function _deployRateKeeper(address pool, bytes32 postfix, bytes memory params)
        internal
        returns (address rateKeeper)
    {
        DeployResult memory deployResult =
            IRateKeeperFactory(latestRateKeeperFactory).deployRateKeeper(pool, postfix, params);

        rateKeeper = deployResult.newContract;

        _executeOnDeploy(latestRateKeeperFactory, deployResult);
    }

    // QUESTION: should be provide any params there?
    function _deployPriceOracle(bytes memory constructorParams) internal returns (address priceOracle) {
        DeployResult memory deployResult =
            IPriceOracleFactory(latestPriceOracleFactory).deployPriceOracle(constructorParams);

        priceOracle = deployResult.newContract;

        _executeOnDeploy(latestPriceOracleFactory, deployResult);
        _setInterestRateModelFactory(priceOracle, latestPriceOracleFactory);
    }

    //
    // FACTORIES
    //
    function _getPoolFactory(address pool) internal view returns (address) {
        return IContractsRegisterExt(contractsRegister).getPoolFactory(pool);
    }

    function _getCreditManagerFactory(address creditManager) internal view returns (address) {
        return IContractsRegisterExt(contractsRegister).getCreditManagerFactory(creditManager);
    }

    function _getPriceOracleFactory(address pool) internal view returns (address) {
        return IContractsRegisterExt(contractsRegister).getPriceOracleFactory(pool);
    }

    function _getRateKeeperFactory(address pool) internal view returns (address) {
        return IContractsRegisterExt(contractsRegister).getRateKeeperFactory(pool);
    }

    function _getInterestRateModelFactory(address model) internal view returns (address) {
        return IContractsRegisterExt(contractsRegister).getInterestRateModelFactory(model);
    }

    function _setPoolFactory(address pool, address factory) internal {
        IContractsRegisterExt(contractsRegister).setPoolFactory(pool, factory);
    }

    function _setCreditManagerFactory(address creditManager, address factory) internal {
        IContractsRegisterExt(contractsRegister).setCreditManagerFactory(creditManager, factory);
    }

    function _setPriceOracleFactory(address pool, address factory) internal {
        IContractsRegisterExt(contractsRegister).setPriceOracleFactory(pool, factory);
    }

    function _setInterestRateModelFactory(address model, address factory) internal {
        IContractsRegisterExt(contractsRegister).setInterestRateModelFactory(model, factory);
    }

    function _setRateKeeperFactory(address pool, address factory) internal {
        IContractsRegisterExt(contractsRegister).setRateKeeperFactory(pool, factory);
    }

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
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                IHook(_getCreditManagerFactory(creditManager)).onAddEmergencyLiquidator(creditManager, liquidator)
            );
        }
    }

    function removeEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.remove(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                IHook(_getCreditManagerFactory(creditManager)).onRemoveEmergencyLiquidator(creditManager, liquidator)
            );
        }
    }

    // QUESTION: should we move it to periphery factory?
    function updateLossLiquidator(address pool, bytes32 postfix, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        // TODO: add deployment here
        address lossLiquidator;
        //  = IContractsFactory(contractsFactory).deployLossLiquidator(pool, postfix, params);

        // @update all credit managers
        address[] memory creditManagers = _creditManagersByPool(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                IHook(_getCreditManagerFactory(creditManager)).onUpdateLossLiquidator(creditManager, lossLiquidator)
            );
        }

        _executeHook(IHook(contractsRegister).onUpdateLossLiquidator(pool, lossLiquidator));
    }

    function configureLossLiquidator(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);

        // address lossLiquidator = lossLiquidators[pool];
        // if (lossLiquidator == address(0)) revert LossLiquidatorNotInitializedException(pool);

        // _safeControllerFunctionCall(lossLiquidator, data);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _getContract(bytes32 postfix, uint256 version_) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(postfix, version_);
    }

    function _getLatestContract(bytes32 postfix) internal view returns (address) {
        return IAddressProvider(addressProvider).getLatestAddressOrRevert(postfix);
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

    function _creditManagersByPool(address pool) internal view returns (address[] memory creditManagers) {
        return IContractsRegisterExt(contractsRegister).getCreditManagersByPool(pool);
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
    // HOOK SAFE EXECUTION
    //
    function _addToAccessList(address factory, address[] memory contracts) internal {
        for (uint256 i; i < contracts.length; ++i) {
            if (accessList[contracts[i]] != address(0)) revert ContractAlreadyInAccessListException(contracts[i]);
            accessList[contracts[i]] = factory;
        }
    }

    function _executeOnDeploy(address factory, DeployResult memory deployResult) internal {
        _addToAccessList(factory, deployResult.accessList);
        _executeHook(HookCheck({factory: factory, calls: deployResult.onInstallOps}));
    }

    function _executeHook(HookCheck memory hookCheck) internal {
        uint256 len = hookCheck.calls.length;
        for (uint256 i; i < len; ++i) {
            Call memory call = hookCheck.calls[i];

            // Check if contract is assigned to factory
            if (accessList[call.target] != hookCheck.factory) revert ContractNotAssignedToFactoryException(call.target);

            (call.target).functionCall(call.callData);
        }
    }

    function _configureFactory(address factory, address target, bytes calldata callData) internal {
        _executeHook(HookCheck({factory: factory, calls: IConfigurableFactory(factory).configure(target, callData)}));
    }

    // QUESTION: switch to role model?
    function emergencyLiquidators() external view override returns (address[] memory) {
        return _emergencyLiquidators.values();
    }
}
