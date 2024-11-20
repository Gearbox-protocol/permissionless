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
import {IRateKeeperFactory} from "../interfaces/IRateKeeperFactory.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {ILossLiquidatorFactory} from "../interfaces/ILossLiquidatorFactory.sol";
import {IInterestRateModelFactory} from "../interfaces/IInterestRateModelFactory.sol";
import {IPriceOracleFactory} from "../interfaces/IPriceOracleFactory.sol";
import {ICreditFactory} from "../interfaces/ICreditFactory.sol";
import {IPoolFactory} from "../interfaces/IPoolFactory.sol";

import {
    AP_MARKET_CONFIGURATOR,
    AP_MARKET_CONFIGURATOR_FACTORY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";

import {ICreditSuiteHooks} from "../interfaces/ICreditSuiteHooks.sol";
import {IMarketHooks} from "../interfaces/IMarketHooks.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";
import {IConfiguratingFactory} from "../interfaces/IConfiguratingFactory.sol";

import {ContractsRegister} from "./ContractsRegister.sol";

// TODO:
// - factories upgradability
// - migration to new market configurator
// - rescue
// - management functions (i.e., shorter timelock but less checks)

/// @title Market configurator
contract MarketConfigurator is Ownable2Step, IMarketConfigurator {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    address public immutable override addressProvider;
    address public immutable override marketConfiguratorFactory;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    EnumerableSet.AddressSet internal _emergencyLiquidators;

    // Access list is additional protection measure to restrict contracts
    // which could be called via hooks.

    /// @notice
    mapping(address contract_ => address factory) public accessList;

    modifier onlySelf() {
        if (msg.sender != address(this)) revert CallerIsNotSelfException();
        _;
    }

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    /// @notice Initializes the MarketConfigurator with the provided parameters.
    /// @param riskCurator_ The address of the risk curator.
    /// @param addressProvider_ The address of the address provider.
    /// @param acl_ The address of the access control list.
    /// @param treasury_ The address of the treasury.
    constructor(address riskCurator_, address addressProvider_, address acl_, address treasury_) {
        _transferOwnership(riskCurator_);
        addressProvider = addressProvider_;
        marketConfiguratorFactory = _getContract(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);

        acl = acl_;
        treasury = treasury_;
        contractsRegister = address(new ContractsRegister(acl));
    }

    /// @notice Contract version
    /// @dev `MarketConfiguratorLegacy` might have different version, hence the `virtual` modifier
    function version() external view virtual override returns (uint256) {
        return 3_10;
    }

    /// @notice Contract type
    /// @dev `MarketConfiguratorLegacy` has different type, hence the `virtual` modifier
    function contractType() external view virtual override returns (bytes32) {
        return AP_MARKET_CONFIGURATOR;
    }

    function callMarketConfiguratorFactory(bytes calldata data) external override onlySelf {
        marketConfiguratorFactory.functionCall(data);
    }

    // ----------------- //
    // MARKET MANAGEMENT //
    // ----------------- //

    function createMarket(
        address underlying,
        string calldata name,
        string calldata symbol,
        DeployParams calldata interestRateModelParams,
        DeployParams calldata rateKeeperParams,
        DeployParams calldata lossLiquidatorParams,
        address underlyingPriceFeed
    ) external override onlyOwner returns (address pool) {
        pool = _deployPool(underlying, name, symbol);
        address priceOracle = _deployPriceOracle(pool);
        address interestRateModel = _deployInterestRateModel(pool, interestRateModelParams);
        address rateKeeper = _deployRateKeeper(pool, rateKeeperParams);
        address lossLiquidator = _deployLossLiquidator(pool, lossLiquidatorParams);

        IContractsRegister(contractsRegister).createMarket(pool, priceOracle);
        _executeMarketHooks(
            pool,
            abi.encodeCall(
                IMarketHooks.onCreateMarket,
                (pool, priceOracle, interestRateModel, rateKeeper, lossLiquidator, underlyingPriceFeed)
            )
        );
    }

    function shutdownMarket(address pool) external override onlyOwner {
        _ensureRegisteredPool(pool);

        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onShutdownMarket, (pool)));
        IContractsRegister(contractsRegister).shutdownMarket(pool);
    }

    function addToken(address pool, address token, address priceFeed) external override onlyOwner {
        _ensureRegisteredPool(pool);

        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onAddToken, (pool, token, priceFeed)));
    }

    function configurePool(address pool, bytes calldata data) external override onlyOwner {
        _ensureRegisteredPool(pool);
        _configureContract(_getPoolFactory(pool), pool, data);
    }

    function _deployPool(address underlying, string calldata name, string calldata symbol)
        internal
        returns (address pool)
    {
        address factory = _getLatestPoolFactory();
        DeployResult memory deployResult = IPoolFactory(factory).deployPool(underlying, name, symbol);
        _executeOnDeploy(factory, deployResult);
        pool = deployResult.newContract;
        _setPoolFactory(pool, factory);
    }

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function createCreditSuite(address pool, bytes calldata encodedParams)
        public
        virtual
        override
        onlyOwner
        returns (address creditManager)
    {
        _ensureRegisteredPool(pool);

        creditManager = _deployCreditSuite(pool, encodedParams);

        IContractsRegister(contractsRegister).createCreditSuite(pool, creditManager);
        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onCreateCreditSuite, (pool, creditManager)));
    }

    function shutdownCreditSuite(address creditManager) external override onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        _executeMarketHooks(
            ICreditManagerV3(creditManager).pool(), abi.encodeCall(IMarketHooks.onShutdownCreditSuite, (creditManager))
        );
        IContractsRegister(contractsRegister).shutdownCreditSuite(creditManager);
    }

    function configureCreditSuite(address creditManager, bytes calldata data) external override onlyOwner {
        _ensureRegisteredCreditManager(creditManager);
        _configureContract(_getCreditFactory(creditManager), creditManager, data);
    }

    function _deployCreditSuite(address pool, bytes calldata encodedParams) internal returns (address creditManager) {
        address factory = _getLatestCreditFactory();
        DeployResult memory deployResult = ICreditFactory(factory).deployCreditSuite(pool, encodedParams);
        _executeOnDeploy(factory, deployResult);
        creditManager = deployResult.newContract;
        _setCreditFactory(creditManager, factory);
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    function updatePriceOracle(address pool) external override onlyOwner returns (address priceOracle) {
        _ensureRegisteredPool(pool);
        address oldPriceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);

        priceOracle = _deployPriceOracle(pool);

        IContractsRegister(contractsRegister).setPriceOracle(pool, priceOracle);
        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onUpdatePriceOracle, (pool, priceOracle, oldPriceOracle)));

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _getCreditFactory(creditManager),
                abi.encodeCall(ICreditSuiteHooks.onUpdatePriceOracle, (creditManager, priceOracle, oldPriceOracle))
            );
        }
    }

    function setPriceFeed(address pool, address token, address priceFeed) external override onlyOwner {
        _ensureRegisteredPool(pool);
        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onSetPriceFeed, (pool, token, priceFeed)));
    }

    function setReservePriceFeed(address pool, address token, address priceFeed) external override onlyOwner {
        _ensureRegisteredPool(pool);
        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onSetReservePriceFeed, (pool, token, priceFeed)));
    }

    function _deployPriceOracle(address pool) internal returns (address priceOracle) {
        address factory = _getLatestPriceOracleFactory();
        DeployResult memory deployResult = IPriceOracleFactory(factory).deployPriceOracle(pool);
        _executeOnDeploy(factory, deployResult);
        priceOracle = deployResult.newContract;
        _setPriceOracleFactory(pool, factory);
    }

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function updateInterestRateModel(address pool, DeployParams calldata params)
        external
        override
        onlyOwner
        returns (address interestRateModel)
    {
        _ensureRegisteredPool(pool);
        address oldInterestRateModel = _interestRateModel(pool);

        interestRateModel = _deployInterestRateModel(pool, params);

        _executeMarketHooks(
            pool,
            abi.encodeCall(IMarketHooks.onUpdateInterestRateModel, (pool, interestRateModel, oldInterestRateModel))
        );
    }

    function configureInterestRateModel(address pool, bytes calldata data) external override onlyOwner {
        _ensureRegisteredPool(pool);
        _configureContract(_getInterestRateModelFactory(pool), _interestRateModel(pool), data);
    }

    function _deployInterestRateModel(address pool, DeployParams calldata params)
        internal
        returns (address interestRateModel)
    {
        address factory = _getLatestInterestRateModelFactory();
        DeployResult memory deployResult = IInterestRateModelFactory(factory).deployInterestRateModel(pool, params);
        _executeOnDeploy(factory, deployResult);
        interestRateModel = deployResult.newContract;
        _setInterestRateModelFactory(pool, factory);
    }

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    function updateRateKeeper(address pool, DeployParams calldata params)
        external
        override
        onlyOwner
        returns (address rateKeeper)
    {
        _ensureRegisteredPool(pool);
        address oldRateKeeper = _rateKeeper(pool);

        rateKeeper = _deployRateKeeper(pool, params);

        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onUpdateRateKeeper, (pool, rateKeeper, oldRateKeeper)));
    }

    function configureRateKeeper(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);
        _configureContract(_getRateKeeperFactory(pool), _rateKeeper(pool), data);
    }

    function _deployRateKeeper(address pool, DeployParams calldata params) internal returns (address rateKeeper) {
        address factory = _getLatestRateKeeperFactory();
        DeployResult memory deployResult = IRateKeeperFactory(factory).deployRateKeeper(pool, params);
        _executeOnDeploy(factory, deployResult);
        rateKeeper = deployResult.newContract;
        _setRateKeeperFactory(pool, factory);
    }

    // -------------------------- //
    // LOSS LIQUIDATOR MANAGEMENT //
    // -------------------------- //

    function updateLossLiquidator(address pool, DeployParams calldata params)
        external
        override
        onlyOwner
        returns (address lossLiquidator)
    {
        _ensureRegisteredPool(pool);
        address oldLossLiquidator = IContractsRegister(contractsRegister).getLossLiquidator(pool);

        lossLiquidator = _deployLossLiquidator(pool, params);

        IContractsRegister(contractsRegister).setLossLiquidator(pool, lossLiquidator);
        _executeMarketHooks(
            pool, abi.encodeCall(IMarketHooks.onUpdateLossLiquidator, (pool, lossLiquidator, oldLossLiquidator))
        );

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _getCreditFactory(creditManager),
                abi.encodeCall(
                    ICreditSuiteHooks.onUpdateLossLiquidator, (creditManager, lossLiquidator, oldLossLiquidator)
                )
            );
        }
    }

    function configureLossLiquidator(address pool, bytes calldata data) external override onlyOwner {
        _ensureRegisteredPool(pool);
        address lossLiquidator = IContractsRegister(pool).getLossLiquidator(pool);
        _configureContract(_getLossLiquidatorFactory(pool), lossLiquidator, data);
    }

    function _deployLossLiquidator(address pool, DeployParams calldata params)
        internal
        returns (address lossLiquidator)
    {
        address factory = _getLatestLossLiquidatorFactory();
        DeployResult memory deployResult = ILossLiquidatorFactory(factory).deployLossLiquidator(pool, params);
        _executeOnDeploy(factory, deployResult);
        lossLiquidator = deployResult.newContract;
        _setLossLiquidatorFactory(pool, factory);
    }

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function addPausableAdmin(address admin) external override onlyOwner {
        IACL(acl).addPausableAdmin(admin);
    }

    function addUnpausableAdmin(address admin) external override onlyOwner {
        IACL(acl).addUnpausableAdmin(admin);
    }

    function removePausableAdmin(address admin) external override onlyOwner {
        IACL(acl).removePausableAdmin(admin);
    }

    function removeUnpausableAdmin(address admin) external override onlyOwner {
        IACL(acl).removeUnpausableAdmin(admin);
    }

    function emergencyLiquidators() external view override returns (address[] memory) {
        return _emergencyLiquidators.values();
    }

    // QUESTION: rewrite using role model?
    function addEmergencyLiquidator(address liquidator) external override onlyOwner {
        if (!_emergencyLiquidators.add(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _getCreditFactory(creditManager),
                abi.encodeCall(ICreditSuiteHooks.onAddEmergencyLiquidator, (creditManager, liquidator))
            );
        }
    }

    function removeEmergencyLiquidator(address liquidator) external override onlyOwner {
        if (!_emergencyLiquidators.remove(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _getCreditFactory(creditManager),
                abi.encodeCall(ICreditSuiteHooks.onRemoveEmergencyLiquidator, (creditManager, liquidator))
            );
        }
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _getContract(bytes32 key, uint256 version_) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(key, version_);
    }

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
            // QUESTION: what happens when we upgrade factory?
            accessList[contracts[i]] = factory;
        }
    }

    function _executeOnDeploy(address factory, DeployResult memory deployResult) internal {
        _addToAccessList(factory, deployResult.accessList);
        _executeHook({factory: factory, calls: deployResult.onInstallOps});
    }

    function _executeMarketHooks(address pool, bytes memory data) internal {
        _executeHook(_getPoolFactory(pool), data);
        _executeHook(_getPriceOracleFactory(pool), data);
        _executeHook(_getInterestRateModelFactory(pool), data);
        _executeHook(_getRateKeeperFactory(pool), data);
        _executeHook(_getLossLiquidatorFactory(pool), data);
    }

    function _executeHook(address factory, bytes memory data) internal {
        _executeHook(factory, abi.decode(factory.functionCall(data), (Call[])));
    }

    /// @dev `MarketConfiguratorLegacy` performs additional checks, hence the `virtual` modifier
    function _executeHook(address factory, Call[] memory calls) internal virtual {
        uint256 len = calls.length;
        for (uint256 i; i < len; ++i) {
            Call memory call = calls[i];
            if (call.target != address(this) && accessList[call.target] != factory) {
                revert ContractNotAssignedToFactoryException(call.target);
            }
            call.target.functionCall(call.callData);
        }
    }

    function _configureContract(address factory, address target, bytes calldata callData) internal {
        _executeHook(factory, IConfiguratingFactory(factory).configure(target, callData));
    }

    function _manageContract(address factory, address target, bytes calldata callData) internal {
        _executeHook(factory, IConfiguratingFactory(factory).manage(target, callData));
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

    // ---- //
    // LMAO //
    // ---- //

    // TODO: all these functions should forward to MarketConfiguratorFactory
    // the only issue is updating the access list when factory is upgraded

    function _getLatestPoolFactory() internal view returns (address factory) {}

    function _setPoolFactory(address pool, address factory) internal {}

    function _getPoolFactory(address pool) internal view returns (address factory) {}

    function _getLatestPriceOracleFactory() internal view returns (address factory) {}

    function _setPriceOracleFactory(address pool, address factory) internal {}

    function _getPriceOracleFactory(address pool) internal view returns (address factory) {}

    function _getLatestInterestRateModelFactory() internal view returns (address factory) {}

    function _setInterestRateModelFactory(address pool, address factory) internal {}

    function _getInterestRateModelFactory(address pool) internal view returns (address factory) {}

    function _getLatestRateKeeperFactory() internal view returns (address factory) {}

    function _setRateKeeperFactory(address pool, address factory) internal {}

    function _getRateKeeperFactory(address pool) internal view returns (address factory) {}

    function _getLatestLossLiquidatorFactory() internal view returns (address factory) {}

    function _setLossLiquidatorFactory(address pool, address factory) internal {}

    function _getLossLiquidatorFactory(address pool) internal view returns (address factory) {}

    function _getLatestCreditFactory() internal view returns (address factory) {}

    function _setCreditFactory(address creditManager, address factory) internal {}

    function _getCreditFactory(address creditManager) internal view returns (address factory) {}
}
