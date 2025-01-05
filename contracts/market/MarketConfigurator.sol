// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {LibString} from "@solady/utils/LibString.sol";

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {ICreditFactory} from "../interfaces/factories/ICreditFactory.sol";
import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IInterestRateModelFactory} from "../interfaces/factories/IInterestRateModelFactory.sol";
import {ILossPolicyFactory} from "../interfaces/factories/ILossPolicyFactory.sol";
import {IMarketFactory} from "../interfaces/factories/IMarketFactory.sol";
import {IPoolFactory} from "../interfaces/factories/IPoolFactory.sol";
import {IPriceOracleFactory} from "../interfaces/factories/IPriceOracleFactory.sol";
import {IRateKeeperFactory} from "../interfaces/factories/IRateKeeperFactory.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {Call, DeployParams, DeployResult, MarketFactories} from "../interfaces/Types.sol";

import {
    AP_CREDIT_FACTORY,
    AP_INTEREST_RATE_MODEL_FACTORY,
    AP_LOSS_POLICY_FACTORY,
    AP_MARKET_CONFIGURATOR,
    AP_MARKET_CONFIGURATOR_FACTORY,
    AP_POOL_FACTORY,
    AP_PRICE_ORACLE_FACTORY,
    AP_RATE_KEEPER_FACTORY,
    NO_VERSION_CONTROL,
    ROLE_PAUSABLE_ADMIN,
    ROLE_UNPAUSABLE_ADMIN
} from "../libraries/ContractLiterals.sol";

import {ACL} from "./ACL.sol";
import {ContractsRegister} from "./ContractsRegister.sol";
import {TreasurySplitter} from "./TreasurySplitter.sol";

/// @title Market configurator
contract MarketConfigurator is IMarketConfigurator {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;
    using LibString for string;
    using LibString for bytes32;

    // --------------- //
    // STATE VARIABLES //
    // --------------- //

    bytes32 internal immutable _curatorName;

    address public immutable override admin;
    address public immutable override emergencyAdmin;

    address public immutable override addressProvider;
    address public immutable override marketConfiguratorFactory;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    mapping(address pool => MarketFactories) internal _marketFactories;
    mapping(address creditManager => address) internal _creditFactories;

    mapping(address target => address) internal _authorizedFactories;
    mapping(address factory => mapping(address suite => EnumerableSet.AddressSet)) internal _factoryTargets;

    // --------- //
    // MODIFIERS //
    // --------- //

    modifier onlySelf() {
        _ensureCallerIsSelf();
        _;
    }

    modifier onlyAdmin() {
        _ensureCallerIsAdmin();
        _;
    }

    modifier onlyEmergencyAdmin() {
        _ensureCallerIsEmergencyAdmin();
        _;
    }

    modifier onlyRegisteredMarket(address pool) {
        _ensureRegisteredMarket(pool);
        _;
    }

    modifier onlyRegisteredCreditSuite(address creditManager) {
        _ensureRegisteredCreditSuite(creditManager);
        _;
    }

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    constructor(string memory curatorName_, address admin_, address emergencyAdmin_, address addressProvider_) {
        _curatorName = curatorName_.toSmallString();
        admin = admin_;
        emergencyAdmin = emergencyAdmin_;

        addressProvider = addressProvider_;
        marketConfiguratorFactory = _getAddressOrRevert(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);

        acl = address(new ACL());
        contractsRegister = address(new ContractsRegister(acl));
        treasury = address(new TreasurySplitter());

        ACL(acl).grantRole(ROLE_PAUSABLE_ADMIN, address(this));
        ACL(acl).grantRole(ROLE_UNPAUSABLE_ADMIN, address(this));
    }

    // -------- //
    // METADATA //
    // -------- //

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

    /// @notice Curator name
    function curatorName() external view override returns (string memory) {
        return _curatorName.fromSmallString();
    }

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function grantRole(bytes32 role, address account) external override onlyAdmin {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external override onlyAdmin {
        _revokeRole(role, account);
    }

    function emergencyRevokeRole(bytes32 role, address account) external override onlyEmergencyAdmin {
        _revokeRole(role, account);
    }

    // ----------------- //
    // MARKET MANAGEMENT //
    // ----------------- //

    function createMarket(
        uint256 minorVersion,
        address underlying,
        string calldata name,
        string calldata symbol,
        DeployParams calldata interestRateModelParams,
        DeployParams calldata rateKeeperParams,
        DeployParams calldata lossPolicyParams,
        address underlyingPriceFeed
    ) external override onlyAdmin returns (address pool) {
        MarketFactories memory factories = _getLatestMarketFactories(minorVersion);
        pool = _deployPool(factories.poolFactory, underlying, name, symbol);
        address priceOracle = _deployPriceOracle(factories.priceOracleFactory, pool);
        address interestRateModel =
            _deployInterestRateModel(factories.interestRateModelFactory, pool, interestRateModelParams);
        address rateKeeper = _deployRateKeeper(factories.rateKeeperFactory, pool, rateKeeperParams);
        address lossPolicy = _deployLossPolicy(factories.lossPolicyFactory, pool, lossPolicyParams);
        _marketFactories[pool] = factories;

        _registerMarket(pool, priceOracle, lossPolicy);
        _executeMarketHooks(
            pool,
            abi.encodeCall(
                IMarketFactory.onCreateMarket,
                (pool, priceOracle, interestRateModel, rateKeeper, lossPolicy, underlyingPriceFeed)
            )
        );
    }

    function shutdownMarket(address pool) external override onlyAdmin onlyRegisteredMarket(pool) {
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onShutdownMarket, (pool)));
        ContractsRegister(contractsRegister).shutdownMarket(pool);
    }

    function addToken(address pool, address token, address priceFeed)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
    {
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onAddToken, (pool, token, priceFeed)));
    }

    function configurePool(address pool, bytes calldata data) external override onlyAdmin onlyRegisteredMarket(pool) {
        _configure(_marketFactories[pool].poolFactory, pool, data);
    }

    function emergencyConfigurePool(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_marketFactories[pool].poolFactory, pool, data);
    }

    function _deployPool(address factory, address underlying, string calldata name, string calldata symbol)
        internal
        returns (address)
    {
        DeployResult memory deployResult = IPoolFactory(factory).deployPool(underlying, name, symbol);
        _executeHook(factory, deployResult.onInstallOps);
        return deployResult.newContract;
    }

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    function createCreditSuite(uint256 minorVersion, address pool, bytes calldata encodedParams)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
        returns (address creditManager)
    {
        address factory = _getLatestCreditFactory(minorVersion);
        creditManager = _deployCreditSuite(factory, pool, encodedParams);
        _creditFactories[creditManager] = factory;

        _registerCreditSuite(creditManager);
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onCreateCreditSuite, (creditManager)));
    }

    function shutdownCreditSuite(address creditManager)
        external
        override
        onlyAdmin
        onlyRegisteredCreditSuite(creditManager)
    {
        _executeMarketHooks(
            ICreditManagerV3(creditManager).pool(),
            abi.encodeCall(IMarketFactory.onShutdownCreditSuite, (creditManager))
        );
        ContractsRegister(contractsRegister).shutdownCreditSuite(creditManager);
    }

    function configureCreditSuite(address creditManager, bytes calldata data)
        external
        override
        onlyAdmin
        onlyRegisteredCreditSuite(creditManager)
    {
        _configure(_creditFactories[creditManager], creditManager, data);
    }

    function emergencyConfigureCreditSuite(address creditManager, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredCreditSuite(creditManager)
    {
        _emergencyConfigure(_creditFactories[creditManager], creditManager, data);
    }

    function _deployCreditSuite(address factory, address pool, bytes calldata encodedParams)
        internal
        returns (address)
    {
        DeployResult memory deployResult = ICreditFactory(factory).deployCreditSuite(pool, encodedParams);
        _executeHook(factory, deployResult.onInstallOps);
        return deployResult.newContract;
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    function updatePriceOracle(address pool)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
        returns (address priceOracle)
    {
        address oldPriceOracle = ContractsRegister(contractsRegister).getPriceOracle(pool);
        priceOracle = _deployPriceOracle(_marketFactories[pool].priceOracleFactory, pool);

        ContractsRegister(contractsRegister).setPriceOracle(pool, priceOracle);
        _executeMarketHooks(
            pool, abi.encodeCall(IMarketFactory.onUpdatePriceOracle, (pool, priceOracle, oldPriceOracle))
        );

        address[] memory creditManagers = _registeredCreditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _creditFactories[creditManager],
                abi.encodeCall(ICreditFactory.onUpdatePriceOracle, (creditManager, priceOracle, oldPriceOracle))
            );
        }
    }

    function configurePriceOracle(address pool, bytes calldata data)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
    {
        _configure(_marketFactories[pool].priceOracleFactory, pool, data);
    }

    function emergencyConfigurePriceOracle(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_marketFactories[pool].priceOracleFactory, pool, data);
    }

    function _deployPriceOracle(address factory, address pool) internal returns (address) {
        DeployResult memory deployResult = IPriceOracleFactory(factory).deployPriceOracle(pool);
        _executeHook(factory, deployResult.onInstallOps);
        return deployResult.newContract;
    }

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function updateInterestRateModel(address pool, DeployParams calldata params)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
        returns (address interestRateModel)
    {
        address oldInterestRateModel = _interestRateModel(pool);
        interestRateModel = _deployInterestRateModel(_marketFactories[pool].interestRateModelFactory, pool, params);

        _executeMarketHooks(
            pool,
            abi.encodeCall(IMarketFactory.onUpdateInterestRateModel, (pool, interestRateModel, oldInterestRateModel))
        );
    }

    function configureInterestRateModel(address pool, bytes calldata data)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
    {
        _configure(_marketFactories[pool].interestRateModelFactory, pool, data);
    }

    function emergencyConfigureInterestRateModel(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_marketFactories[pool].interestRateModelFactory, pool, data);
    }

    function _deployInterestRateModel(address factory, address pool, DeployParams calldata params)
        internal
        returns (address)
    {
        DeployResult memory deployResult = IInterestRateModelFactory(factory).deployInterestRateModel(pool, params);
        _executeHook(factory, deployResult.onInstallOps);
        return deployResult.newContract;
    }

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    function updateRateKeeper(address pool, DeployParams calldata params)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
        returns (address rateKeeper)
    {
        address oldRateKeeper = _rateKeeper(_quotaKeeper(pool));
        rateKeeper = _deployRateKeeper(_marketFactories[pool].rateKeeperFactory, pool, params);

        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onUpdateRateKeeper, (pool, rateKeeper, oldRateKeeper)));
    }

    function configureRateKeeper(address pool, bytes calldata data)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
    {
        _configure(_marketFactories[pool].rateKeeperFactory, pool, data);
    }

    function emergencyConfigureRateKeeper(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_marketFactories[pool].rateKeeperFactory, pool, data);
    }

    function _deployRateKeeper(address factory, address pool, DeployParams calldata params)
        internal
        returns (address)
    {
        DeployResult memory deployResult = IRateKeeperFactory(factory).deployRateKeeper(pool, params);
        _executeHook(factory, deployResult.onInstallOps);
        return deployResult.newContract;
    }

    // ---------------------- //
    // LOSS POLICY MANAGEMENT //
    // ---------------------- //

    function updateLossPolicy(address pool, DeployParams calldata params)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
        returns (address lossPolicy)
    {
        address oldLossPolicy = ContractsRegister(contractsRegister).getLossPolicy(pool);
        lossPolicy = _deployLossPolicy(_marketFactories[pool].lossPolicyFactory, pool, params);

        ContractsRegister(contractsRegister).setLossPolicy(pool, lossPolicy);
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onUpdateLossPolicy, (pool, lossPolicy, oldLossPolicy)));

        address[] memory creditManagers = _registeredCreditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _creditFactories[creditManager],
                abi.encodeCall(ICreditFactory.onUpdateLossPolicy, (creditManager, lossPolicy, oldLossPolicy))
            );
        }
    }

    function configureLossPolicy(address pool, bytes calldata data)
        external
        override
        onlyAdmin
        onlyRegisteredMarket(pool)
    {
        _configure(_marketFactories[pool].lossPolicyFactory, pool, data);
    }

    function emergencyConfigureLossPolicy(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_marketFactories[pool].lossPolicyFactory, pool, data);
    }

    function _deployLossPolicy(address factory, address pool, DeployParams calldata params)
        internal
        returns (address)
    {
        DeployResult memory deployResult = ILossPolicyFactory(factory).deployLossPolicy(pool, params);
        _executeHook(factory, deployResult.onInstallOps);
        return deployResult.newContract;
    }

    // --------- //
    // FACTORIES //
    // --------- //

    function getMarketFactories(address pool) external view override returns (MarketFactories memory) {
        return _marketFactories[pool];
    }

    function getCreditFactory(address creditManager) external view override returns (address) {
        return _creditFactories[creditManager];
    }

    function getAuthorizedFactory(address target) external view override returns (address) {
        return _authorizedFactories[target];
    }

    function getFactoryTargets(address factory, address suite) external view override returns (address[] memory) {
        return _factoryTargets[factory][suite].values();
    }

    function authorizeFactory(address factory, address suite, address target) external override onlySelf {
        if (_authorizedFactories[target] != address(0)) revert UnauthorizedFactoryException(factory, target);
        _authorizeFactory(factory, suite, target);
    }

    function unauthorizeFactory(address factory, address suite, address target) external override onlySelf {
        if (_authorizedFactories[target] != factory) revert UnauthorizedFactoryException(factory, target);
        _unauthorizeFactory(factory, suite, target);
    }

    function upgradePoolFactory(address pool) external override onlyAdmin {
        address oldFactory = _marketFactories[pool].poolFactory;
        address newFactory = _getLatestPatch(oldFactory);
        if (newFactory == oldFactory) return;
        _marketFactories[pool].poolFactory = newFactory;
        _migrateFactoryTargets(oldFactory, newFactory, pool);
    }

    function upgradePriceOracleFactory(address pool) external override onlyAdmin {
        address oldFactory = _marketFactories[pool].priceOracleFactory;
        address newFactory = _getLatestPatch(oldFactory);
        if (newFactory == oldFactory) return;
        _marketFactories[pool].priceOracleFactory = newFactory;
        _migrateFactoryTargets(oldFactory, newFactory, pool);
    }

    function upgradeInterestRateModelFactory(address pool) external override onlyAdmin {
        address oldFactory = _marketFactories[pool].interestRateModelFactory;
        address newFactory = _getLatestPatch(oldFactory);
        if (newFactory == oldFactory) return;
        _marketFactories[pool].interestRateModelFactory = newFactory;
        _migrateFactoryTargets(oldFactory, newFactory, pool);
    }

    function upgradeRateKeeperFactory(address pool) external override onlyAdmin {
        address oldFactory = _marketFactories[pool].rateKeeperFactory;
        address newFactory = _getLatestPatch(oldFactory);
        if (newFactory == oldFactory) return;
        _marketFactories[pool].rateKeeperFactory = newFactory;
        _migrateFactoryTargets(oldFactory, newFactory, pool);
    }

    function upgradeLossPolicyFactory(address pool) external override onlyAdmin {
        address oldFactory = _marketFactories[pool].lossPolicyFactory;
        address newFactory = _getLatestPatch(oldFactory);
        if (newFactory == oldFactory) return;
        _marketFactories[pool].lossPolicyFactory = newFactory;
        _migrateFactoryTargets(oldFactory, newFactory, pool);
    }

    function upgradeCreditFactory(address creditManager) external override onlyAdmin {
        address oldFactory = _creditFactories[creditManager];
        address newFactory = _getLatestPatch(oldFactory);
        if (newFactory == oldFactory) return;
        _creditFactories[creditManager] = newFactory;
        _migrateFactoryTargets(oldFactory, newFactory, creditManager);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _ensureCallerIsSelf() internal view {
        if (msg.sender != address(this)) revert CallerIsNotSelfException(msg.sender);
    }

    function _ensureCallerIsAdmin() internal view {
        if (msg.sender != admin) revert CallerIsNotAdminException(msg.sender);
    }

    function _ensureCallerIsEmergencyAdmin() internal view {
        if (msg.sender != emergencyAdmin) revert CallerIsNotEmergencyAdminException(msg.sender);
    }

    function _ensureRegisteredMarket(address pool) internal view {
        if (!ContractsRegister(contractsRegister).isPool(pool)) {
            revert MarketNotRegisteredException(pool);
        }
    }

    function _ensureRegisteredCreditSuite(address creditManager) internal view {
        if (!ContractsRegister(contractsRegister).isCreditManager(creditManager)) {
            revert CreditSuiteNotRegisteredException(creditManager);
        }
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function _grantRole(bytes32 role, address account) internal virtual {
        ACL(acl).grantRole(role, account);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function _revokeRole(bytes32 role, address account) internal virtual {
        ACL(acl).revokeRole(role, account);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function _registerMarket(address pool, address priceOracle, address lossPolicy) internal virtual {
        ContractsRegister(contractsRegister).registerMarket(pool, priceOracle, lossPolicy);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function _registerCreditSuite(address creditManager) internal virtual {
        ContractsRegister(contractsRegister).registerCreditSuite(creditManager);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional checks, hence the `virtual` modifier
    function _validateCallTarget(address target, address factory) internal virtual {
        if (target != address(this) && target != marketConfiguratorFactory && _authorizedFactories[target] != factory) {
            revert UnauthorizedFactoryException(factory, target);
        }
    }

    function _getAddressOrRevert(bytes32 key, uint256 ver) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(key, ver);
    }

    function _getLatestPatch(bytes32 key, uint256 minorVersion) internal view returns (address) {
        return _getAddressOrRevert(
            key, IAddressProvider(addressProvider).getLatestPatchVersion(key.fromSmallString(), minorVersion)
        );
    }

    function _getLatestPatch(address factory) internal view returns (address) {
        return _getLatestPatch(IVersion(factory).contractType(), IVersion(factory).version());
    }

    function _getLatestMarketFactories(uint256 minorVersion) internal view returns (MarketFactories memory) {
        return MarketFactories({
            poolFactory: _getLatestPatch(AP_POOL_FACTORY, minorVersion),
            priceOracleFactory: _getLatestPatch(AP_PRICE_ORACLE_FACTORY, minorVersion),
            interestRateModelFactory: _getLatestPatch(AP_INTEREST_RATE_MODEL_FACTORY, minorVersion),
            rateKeeperFactory: _getLatestPatch(AP_RATE_KEEPER_FACTORY, minorVersion),
            lossPolicyFactory: _getLatestPatch(AP_LOSS_POLICY_FACTORY, minorVersion)
        });
    }

    function _getLatestCreditFactory(uint256 minorVersion) internal view returns (address) {
        return _getLatestPatch(AP_CREDIT_FACTORY, minorVersion);
    }

    function _authorizeFactory(address factory, address suite, address target) internal {
        _authorizedFactories[target] = factory;
        _factoryTargets[factory][suite].add(target);
        emit AuthorizeFactory(factory, suite, target);
    }

    function _unauthorizeFactory(address factory, address suite, address target) internal {
        _authorizedFactories[target] = address(0);
        _factoryTargets[factory][suite].remove(target);
        emit UnauthorizeFactory(factory, suite, target);
    }

    function _migrateFactoryTargets(address oldFactory, address newFactory, address suite) internal {
        EnumerableSet.AddressSet storage targets = _factoryTargets[oldFactory][suite];
        uint256 numTargets = targets.length();
        for (uint256 i; i < numTargets; ++i) {
            address target = targets.at(i);
            targets.remove(target);
            _factoryTargets[newFactory][suite].add(target);
            _authorizedFactories[target] = newFactory;
            emit UnauthorizeFactory(oldFactory, suite, target);
            emit AuthorizeFactory(newFactory, suite, target);
        }
    }

    function _executeMarketHooks(address pool, bytes memory data) internal {
        MarketFactories memory factories = _marketFactories[pool];
        _executeHook(factories.poolFactory, data);
        _executeHook(factories.priceOracleFactory, data);
        _executeHook(factories.interestRateModelFactory, data);
        _executeHook(factories.rateKeeperFactory, data);
        _executeHook(factories.lossPolicyFactory, data);
    }

    function _executeHook(address factory, bytes memory data) internal {
        _executeHook(factory, abi.decode(factory.functionCall(data), (Call[])));
    }

    function _configure(address factory, address target, bytes calldata callData) internal {
        _executeHook(factory, IFactory(factory).configure(target, callData));
    }

    function _emergencyConfigure(address factory, address target, bytes calldata callData) internal {
        _executeHook(factory, IFactory(factory).emergencyConfigure(target, callData));
    }

    function _executeHook(address factory, Call[] memory calls) internal {
        uint256 len = calls.length;
        for (uint256 i; i < len; ++i) {
            address target = calls[i].target;
            _validateCallTarget(target, factory);
            target.functionCall(calls[i].callData);
        }
    }

    function _registeredCreditManagers() internal view returns (address[] memory) {
        return ContractsRegister(contractsRegister).getCreditManagers();
    }

    function _registeredCreditManagers(address pool) internal view returns (address[] memory creditManagers) {
        return ContractsRegister(contractsRegister).getCreditManagers(pool);
    }

    function _quotaKeeper(address pool) internal view returns (address) {
        return IPoolV3(pool).poolQuotaKeeper();
    }

    function _interestRateModel(address pool) internal view returns (address) {
        return IPoolV3(pool).interestRateModel();
    }

    function _rateKeeper(address quotaKeeper) internal view returns (address) {
        return IPoolQuotaKeeperV3(quotaKeeper).gauge();
    }
}
