// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {IACL} from "../interfaces/extensions/IACL.sol";
import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";
import {IRateKeeperFactory} from "../interfaces/IRateKeeperFactory.sol";
import {IMarketConfigurator, CreateMarketParams} from "../interfaces/IMarketConfigurator.sol";
import {IInterestRateModelFactory} from "../interfaces/IInterestRateModelFactory.sol";
import {IPriceOracleFactory} from "../interfaces/IPriceOracleFactory.sol";
import {ICreditFactory} from "../interfaces/ICreditFactory.sol";
import {IPoolFactory} from "../interfaces/IPoolFactory.sol";

import {AP_MARKET_CONFIGURATOR, AP_PRICE_FEED_STORE} from "../libraries/ContractLiterals.sol";

import {Call, DeployResult} from "../interfaces/Types.sol";
import {IConfiguratingFactory} from "../interfaces/IConfiguratingFactory.sol";

import {ICreditHooks} from "../interfaces/ICreditHooks.sol";
import {IHook, HookCheck, HookExecutor} from "../libraries/Hook.sol";

// TODO:
// - degen NFT management
// - migration to new market configurator
// - rescue

/// @title Market configurator
contract MarketConfigurator is Ownable2Step, IMarketConfigurator {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;
    using HookExecutor for IHook;

    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR;

    address public immutable override addressProvider;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    address latestInterestRateModelFactory;
    address latestPoolFactory;
    address latestRateKeeperFactory;
    address latestPriceOracleFactory;
    address latestCreditFactory;
    address gearStakingFactory;

    // TODO: potentially move to contracts register as well
    // ACL seems to be a better place for it though since this list is the same for all markets
    EnumerableSet.AddressSet internal _emergencyLiquidators;

    // Access list is additional protection measure to restrict contracts
    // which could be called via hooks.

    /// @notice
    mapping(address contract_ => address factory) public accessList;

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    /// @notice Initializes the MarketConfigurator with the provided parameters.
    /// @param riskCurator_ The address of the risk curator.
    /// @param addressProvider_ The address of the address provider.
    /// @param acl_ The address of the access control list.
    /// @param contractsRegister_ The address of the contracts register.
    /// @param treasury_ The address of the treasury.
    constructor(
        address riskCurator_,
        address addressProvider_,
        address acl_,
        address contractsRegister_,
        address treasury_
    ) {
        _transferOwnership(riskCurator_);
        addressProvider = addressProvider_;
        acl = acl_;
        contractsRegister = contractsRegister_;
        treasury = treasury_;
    }

    // QUESTION: switch to role model?
    function emergencyLiquidators() external view override returns (address[] memory) {
        return _emergencyLiquidators.values();
    }

    // ----------------- //
    // MARKET MANAGEMENT //
    // ----------------- //

    /**
     * @notice Creates a new market with the specified parameters
     * @param params A struct containing all the necessary parameters for market creation:
     *        - underlying: The address of the underlying asset for the market
     *        - symbol: The symbol for the market
     *        - name: The name for the market
     *        - poolParams: Encoded parameters for pool creation
     *        - underlyingPriceFeed: The address of the price feed for the underlying asset
     *        - priceOracleParams: Encoded parameters for price oracle creation
     *        - irmPostfix: The postfix for the Interest Rate Model
     *        - irmParams: Encoded parameters for Interest Rate Model creation
     *        - rateKeeperPostfix: The postfix for the Rate Keeper
     *        - rateKeeperParams: Encoded parameters for Rate Keeper creation
     */
    function createMarket(CreateMarketParams calldata params) external onlyOwner returns (address pool) {
        DeployResult memory deployResult =
            IPoolFactory(latestPoolFactory).deployPool(params.underlying, params.name, params.symbol);
        _executeOnDeploy(latestPoolFactory, deployResult);
        pool = deployResult.newContract;

        address priceOracle = _deployPriceOracle(params.priceOracleParams);

        IContractsRegister(contractsRegister).createMarket(pool, priceOracle);
        _setPoolFactory(pool, latestPoolFactory);
        _setPriceOracleFactory(pool, latestPriceOracleFactory);

        _setPriceFeed(pool, params.underlying, params.underlyingPriceFeed);
        _updateInterestRateModel(pool, params.irmPostfix, params.irmParams);
        _updateRateKeeper(pool, params.rateKeeperPostfix, params.rateKeeperParams);
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

        IContractsRegister(contractsRegister).shutdownMarket(pool);
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

        _executeHook(IHook(_getPriceOracleFactory(pool)).onAddToken(pool, token, priceFeed));
        _executeHook(IHook(_getPoolFactory(pool)).onAddToken(pool, token, priceFeed));
        _executeHook(IHook(_getRateKeeperFactory(pool)).onAddToken(pool, token, priceFeed));
    }

    function configurePool(address pool, bytes calldata callData) external onlyOwner {
        _ensureRegisteredPool(pool);
        _configureContract(_getPoolFactory(pool), pool, callData);
    }

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    function createCreditSuite(address pool, bytes calldata encodedParams)
        external
        onlyOwner
        returns (address creditManager)
    {
        _ensureRegisteredPool(pool);

        DeployResult memory deployResult = ICreditFactory(latestCreditFactory).deployCreditSuite(pool, encodedParams);
        _executeOnDeploy(latestCreditFactory, deployResult);

        creditManager = deployResult.newContract;
        _setCreditFactory(creditManager, latestCreditFactory);

        IContractsRegister(contractsRegister).createCreditSuite(pool, creditManager);
        _executeHook(IHook(_getPoolFactory(pool)).onCreateCreditSuite(pool, creditManager));
    }

    function shutdownCreditSuite(address creditManager) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address pool = ICreditManagerV3(creditManager).pool();

        _executeHook(IHook(_getCreditFactory(creditManager)).onShutdownCreditSuite(pool, creditManager));
        _executeHook(IHook(_getPoolFactory(pool)).onShutdownCreditSuite(pool, creditManager));

        IContractsRegister(contractsRegister).shutdownCreditSuite(creditManager);
    }

    function configureCreditSuite(address creditManager, bytes calldata data) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);
        _configureContract(_getCreditFactory(creditManager), creditManager, data);
    }

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function updateInterestRateModel(address pool, bytes32 postfix, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);
        _updateInterestRateModel(pool, postfix, params);
    }

    function configureInterestRateModel(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        _configureContract(_getInterestRateModelFactory(pool), _interestRateModel(pool), data);
    }

    function _updateInterestRateModel(address pool, bytes32 postfix, bytes calldata params) internal {
        address irm = _deployInterestRateModel(postfix, params);
        _setInterestRateModelFactory(pool, latestInterestRateModelFactory);
        _executeHook(IHook(_getPoolFactory(pool)).onUpdateInterestRateModel(pool, irm));
        // which hooks should be added?
    }

    function _deployInterestRateModel(bytes32 postfix, bytes memory params) internal returns (address) {
        DeployResult memory deployResult =
            IInterestRateModelFactory(latestInterestRateModelFactory).deployInterestRateModel(postfix, params);
        _executeOnDeploy(latestInterestRateModelFactory, deployResult);
        return deployResult.newContract;
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    function updatePriceOracle(address pool, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address priceOracle = _deployPriceOracle(params);
        address prevPriceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);

        _setPriceOracleFactory(pool, latestPriceOracleFactory);

        _executeHook(IHook(latestPriceOracleFactory).onUpdatePriceOracle(pool, priceOracle, prevPriceOracle));
        IContractsRegister(contractsRegister).setPriceOracle(pool, priceOracle);

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                IHook(_getCreditFactory(creditManager)).onUpdatePriceOracle(creditManager, priceOracle, prevPriceOracle)
            );
        }
    }

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

    function setReservePriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        // set price feed
        _executeHook(IHook(_getPriceOracleFactory(pool)).onSetReservePriceFeed(pool, token, priceFeed));
        _executeHook(IHook(_getPoolFactory(pool)).onSetReservePriceFeed(pool, token, priceFeed));
    }

    function _deployPriceOracle(bytes memory constructorParams) internal returns (address) {
        DeployResult memory deployResult =
            IPriceOracleFactory(latestPriceOracleFactory).deployPriceOracle(constructorParams);
        _executeOnDeploy(latestPriceOracleFactory, deployResult);
        return deployResult.newContract;
    }

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    function updateRateKeeper(address pool, bytes32 postfix, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);
        // TODO: check if rate keeper is already set (it is set for sure)
        // then execute onRemoveRateKeeper hook
        _updateRateKeeper(pool, postfix, params);
    }

    function configureRateKeeper(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        _configureContract(_getRateKeeperFactory(pool), _rateKeeper(pool), data);
    }

    function _updateRateKeeper(address pool, bytes32 postfix, bytes calldata params) internal {
        address rateKeeper = _deployRateKeeper(pool, postfix, params);
        _setRateKeeperFactory(pool, latestRateKeeperFactory);

        _executeHook(IHook(_getPoolFactory(pool)).onUpdateRateKeeper(pool, rateKeeper));
        _executeHook(IHook(gearStakingFactory).onUpdateRateKeeper(pool, rateKeeper));
    }

    function _deployRateKeeper(address pool, bytes32 postfix, bytes memory params) internal returns (address) {
        DeployResult memory deployResult =
            IRateKeeperFactory(latestRateKeeperFactory).deployRateKeeper(pool, postfix, params);
        _executeOnDeploy(latestRateKeeperFactory, deployResult);
        return deployResult.newContract;
    }

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function addPausableAdmin(address admin) external onlyOwner {
        IACL(acl).addPausableAdmin(admin);
    }

    function addUnpausableAdmin(address admin) external onlyOwner {
        IACL(acl).addUnpausableAdmin(admin);
    }

    function removePausableAdmin(address admin) external onlyOwner {
        IACL(acl).removePausableAdmin(admin);
    }

    function removeUnpausableAdmin(address admin) external onlyOwner {
        IACL(acl).removeUnpausableAdmin(admin);
    }

    // QUESTION: rewrite using role model?
    function addEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.add(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(IHook(_getCreditFactory(creditManager)).onAddEmergencyLiquidator(creditManager, liquidator));
        }
    }

    function removeEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.remove(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(IHook(_getCreditFactory(creditManager)).onRemoveEmergencyLiquidator(creditManager, liquidator));
        }
    }

    // QUESTION: should we move it to periphery factory?
    function updateLossLiquidator(address pool, bytes32 postfix, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        // TODO: add deployment here
        address lossLiquidator;
        //  = IContractsFactory(contractsFactory).deployLossLiquidator(pool, postfix, params);

        // @update all credit managers
        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(IHook(_getCreditFactory(creditManager)).onUpdateLossLiquidator(creditManager, lossLiquidator));
        }

        IContractsRegister(contractsRegister).setLossLiquidator(pool, lossLiquidator);
    }

    function configureLossLiquidator(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        address lossLiquidator = IContractsRegister(contractsRegister).getLossLiquidator(pool);
        // _safeControllerFunctionCall(lossLiquidator, data);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _ensureRegisteredPool(address pool) internal view {
        if (!IContractsRegister(contractsRegister).isPool(pool)) {
            revert RegisteredPoolOnlyException();
        }
    }

    function _ensureRegisteredCreditManager(address creditManager) internal view {
        if (!IContractsRegister(contractsRegister).isCreditManager(creditManager)) {
            revert RegisteredCreditManagerOnlyException();
        }
    }

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
            if (accessList[call.target] != hookCheck.factory) revert ContractNotAssignedToFactoryException(call.target);
            call.target.functionCall(call.callData);
        }
    }

    function _configureContract(address factory, address target, bytes calldata callData) internal {
        _executeHook(HookCheck({factory: factory, calls: IConfiguratingFactory(factory).configure(target, callData)}));
    }

    function _creditManagers() internal view returns (address[] memory) {
        return IContractsRegister(contractsRegister).getCreditManagers();
    }

    function _creditManagers(address pool) internal view returns (address[] memory creditManagers) {
        return IContractsRegister(contractsRegister).getCreditManagers(pool);
    }

    function _interestRateModel(address pool) internal view returns (address) {
        return IPoolV3(pool).interestRateModel();
    }

    function _rateKeeper(address pool) internal view returns (address) {
        return IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge();
    }

    function _getPoolFactory(address pool) internal view returns (address) {
        return IContractsRegister(contractsRegister).getPoolFactory(pool);
    }

    function _getCreditFactory(address creditManager) internal view returns (address) {
        return IContractsRegister(contractsRegister).getCreditFactory(creditManager);
    }

    function _getPriceOracleFactory(address pool) internal view returns (address) {
        return IContractsRegister(contractsRegister).getPriceOracleFactory(pool);
    }

    function _getRateKeeperFactory(address pool) internal view returns (address) {
        return IContractsRegister(contractsRegister).getRateKeeperFactory(pool);
    }

    function _getInterestRateModelFactory(address pool) internal view returns (address) {
        return IContractsRegister(contractsRegister).getInterestRateModelFactory(pool);
    }

    function _setPoolFactory(address pool, address factory) internal {
        IContractsRegister(contractsRegister).setPoolFactory(pool, factory);
    }

    function _setCreditFactory(address creditManager, address factory) internal {
        IContractsRegister(contractsRegister).setCreditFactory(creditManager, factory);
    }

    function _setPriceOracleFactory(address pool, address factory) internal {
        IContractsRegister(contractsRegister).setPriceOracleFactory(pool, factory);
    }

    function _setInterestRateModelFactory(address pool, address factory) internal {
        IContractsRegister(contractsRegister).setInterestRateModelFactory(pool, factory);
    }

    function _setRateKeeperFactory(address pool, address factory) internal {
        IContractsRegister(contractsRegister).setRateKeeperFactory(pool, factory);
    }
}
