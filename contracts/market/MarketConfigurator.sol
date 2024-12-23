// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {LibString} from "@solady/utils/LibString.sol";

import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {ICreditFactory} from "../interfaces/factories/ICreditFactory.sol";
import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IInterestRateModelFactory} from "../interfaces/factories/IInterestRateModelFactory.sol";
import {ILossLiquidatorFactory} from "../interfaces/factories/ILossLiquidatorFactory.sol";
import {IMarketFactory} from "../interfaces/factories/IMarketFactory.sol";
import {IPoolFactory} from "../interfaces/factories/IPoolFactory.sol";
import {IPriceOracleFactory} from "../interfaces/factories/IPriceOracleFactory.sol";
import {IRateKeeperFactory} from "../interfaces/factories/IRateKeeperFactory.sol";

import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {AP_MARKET_CONFIGURATOR, ROLE_PAUSABLE_ADMIN, ROLE_UNPAUSABLE_ADMIN} from "../libraries/ContractLiterals.sol";

import {ACL} from "./ACL.sol";
import {ContractsRegister} from "./ContractsRegister.sol";
import {TreasurySplitter} from "../market/TreasurySplitter.sol";

/// @title Market configurator
contract MarketConfigurator is Ownable2Step, IMarketConfigurator {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    // --------------- //
    // STATE VARIABLES //
    // --------------- //

    address public immutable override marketConfiguratorFactory;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    address public override emergencyAdmin;

    mapping(address target => address factory) public override accessList;
    // FIXME: this actually might contain targets for multiple markets/credit suites
    mapping(address factory => EnumerableSet.AddressSet) internal _authorizedTargets;

    bytes32 internal immutable _name;

    // --------- //
    // MODIFIERS //
    // --------- //

    modifier onlyMarketConfiguratorFactory() {
        if (msg.sender != marketConfiguratorFactory) revert CallerIsNotMarketConfiguratorFactoryException();
        _;
    }

    modifier onlyEmergencyAdmin() {
        if (msg.sender != emergencyAdmin) revert CallerIsNotEmergencyAdminException();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert CallerIsNotSelfException();
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

    constructor(string memory name_, address marketConfiguratorFactory_, address admin_, address emergencyAdmin_) {
        marketConfiguratorFactory = marketConfiguratorFactory_;
        transferOwnership(admin_);
        emergencyAdmin = emergencyAdmin_;
        // FIXME: okay, these should, in fact, be deployed via factory in case we migrate
        acl = address(new ACL());
        contractsRegister = address(new ContractsRegister(acl));
        // TODO: transfer ownership to the 2/2 multisig of `msg.sender` and DAO (to be introduced)
        treasury = address(new TreasurySplitter());
        _name = LibString.toSmallString(name_);

        _grantRole(ROLE_PAUSABLE_ADMIN, address(this));
        _grantRole(ROLE_UNPAUSABLE_ADMIN, address(this));
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

    /// @notice Contract name
    function contractName() external view override returns (string memory) {
        return LibString.fromSmallString(_name);
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

        _registerMarket(pool, priceOracle, lossLiquidator);
        _executeMarketHooks(
            pool,
            abi.encodeCall(
                IMarketFactory.onCreateMarket,
                (pool, priceOracle, interestRateModel, rateKeeper, lossLiquidator, underlyingPriceFeed)
            )
        );
    }

    function shutdownMarket(address pool) external override onlyOwner onlyRegisteredMarket(pool) {
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onShutdownMarket, (pool)));
        ContractsRegister(contractsRegister).shutdownMarket(pool);
    }

    function addToken(address pool, address token, address priceFeed)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
    {
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onAddToken, (pool, token, priceFeed)));
    }

    function configurePool(address pool, bytes calldata data) external override onlyOwner onlyRegisteredMarket(pool) {
        _configure(_getPoolFactory(pool), pool, data);
    }

    function emergencyConfigurePool(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_getPoolFactory(pool), pool, data);
    }

    function _deployPool(address underlying, string calldata name, string calldata symbol)
        internal
        returns (address pool)
    {
        address factory = _getLatestPoolFactory();
        DeployResult memory deployResult = IPoolFactory(factory).deployPool(underlying, name, symbol);
        _executeHook(factory, deployResult.onInstallOps);
        pool = deployResult.newContract;
        _setPoolFactory(pool, factory);
    }

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    function createCreditSuite(address pool, bytes calldata encodedParams)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
        returns (address creditManager)
    {
        creditManager = _deployCreditSuite(pool, encodedParams);

        _registerCreditSuite(creditManager);
        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onCreateCreditSuite, (creditManager)));
    }

    function shutdownCreditSuite(address creditManager)
        external
        override
        onlyOwner
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
        onlyOwner
        onlyRegisteredCreditSuite(creditManager)
    {
        _configure(_getCreditFactory(creditManager), creditManager, data);
    }

    function emergencyConfigureCreditSuite(address creditManager, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredCreditSuite(creditManager)
    {
        _emergencyConfigure(_getCreditFactory(creditManager), creditManager, data);
    }

    function _deployCreditSuite(address pool, bytes calldata encodedParams) internal returns (address creditManager) {
        address factory = _getLatestCreditFactory();
        DeployResult memory deployResult = ICreditFactory(factory).deployCreditSuite(pool, encodedParams);
        _executeHook(factory, deployResult.onInstallOps);
        creditManager = deployResult.newContract;
        _setCreditFactory(creditManager, factory);
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    function updatePriceOracle(address pool)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
        returns (address priceOracle)
    {
        address oldPriceOracle = ContractsRegister(contractsRegister).getPriceOracle(pool);
        priceOracle = _deployPriceOracle(pool);

        ContractsRegister(contractsRegister).setPriceOracle(pool, priceOracle);
        _executeMarketHooks(
            pool, abi.encodeCall(IMarketFactory.onUpdatePriceOracle, (pool, priceOracle, oldPriceOracle))
        );

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _getCreditFactory(creditManager),
                abi.encodeCall(ICreditFactory.onUpdatePriceOracle, (creditManager, priceOracle, oldPriceOracle))
            );
        }
    }

    function configurePriceOracle(address pool, bytes calldata data)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
    {
        _configure(_getPriceOracleFactory(pool), pool, data);
    }

    function emergencyConfigurePriceOracle(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_getPriceOracleFactory(pool), pool, data);
    }

    function _deployPriceOracle(address pool) internal returns (address priceOracle) {
        address factory = _getLatestPriceOracleFactory();
        DeployResult memory deployResult = IPriceOracleFactory(factory).deployPriceOracle(pool);
        _executeHook(factory, deployResult.onInstallOps);
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
        onlyRegisteredMarket(pool)
        returns (address interestRateModel)
    {
        address oldInterestRateModel = IPoolV3(pool).interestRateModel();
        interestRateModel = _deployInterestRateModel(pool, params);

        _executeMarketHooks(
            pool,
            abi.encodeCall(IMarketFactory.onUpdateInterestRateModel, (pool, interestRateModel, oldInterestRateModel))
        );
    }

    function configureInterestRateModel(address pool, bytes calldata data)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
    {
        _configure(_getInterestRateModelFactory(pool), pool, data);
    }

    function emergencyConfigureInterestRateModel(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_getInterestRateModelFactory(pool), pool, data);
    }

    function _deployInterestRateModel(address pool, DeployParams calldata params)
        internal
        returns (address interestRateModel)
    {
        address factory = _getLatestInterestRateModelFactory();
        DeployResult memory deployResult = IInterestRateModelFactory(factory).deployInterestRateModel(pool, params);
        _executeHook(factory, deployResult.onInstallOps);
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
        onlyRegisteredMarket(pool)
        returns (address rateKeeper)
    {
        address oldRateKeeper = IPoolQuotaKeeperV3(_quotaKeeper(pool)).gauge();
        rateKeeper = _deployRateKeeper(pool, params);

        _executeMarketHooks(pool, abi.encodeCall(IMarketFactory.onUpdateRateKeeper, (pool, rateKeeper, oldRateKeeper)));
    }

    function configureRateKeeper(address pool, bytes calldata data)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
    {
        _configure(_getRateKeeperFactory(pool), pool, data);
    }

    function emergencyConfigureRateKeeper(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_getRateKeeperFactory(pool), pool, data);
    }

    function _deployRateKeeper(address pool, DeployParams calldata params) internal returns (address rateKeeper) {
        address factory = _getLatestRateKeeperFactory();
        DeployResult memory deployResult = IRateKeeperFactory(factory).deployRateKeeper(pool, params);
        _executeHook(factory, deployResult.onInstallOps);
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
        onlyRegisteredMarket(pool)
        returns (address lossLiquidator)
    {
        address oldLossLiquidator = ContractsRegister(contractsRegister).getLossLiquidator(pool);
        lossLiquidator = _deployLossLiquidator(pool, params);

        ContractsRegister(contractsRegister).setLossLiquidator(pool, lossLiquidator);
        _executeMarketHooks(
            pool, abi.encodeCall(IMarketFactory.onUpdateLossLiquidator, (pool, lossLiquidator, oldLossLiquidator))
        );

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            address creditManager = creditManagers[i];
            _executeHook(
                _getCreditFactory(creditManager),
                abi.encodeCall(
                    ICreditFactory.onUpdateLossLiquidator, (creditManager, lossLiquidator, oldLossLiquidator)
                )
            );
        }
    }

    function configureLossLiquidator(address pool, bytes calldata data)
        external
        override
        onlyOwner
        onlyRegisteredMarket(pool)
    {
        _configure(_getLossLiquidatorFactory(pool), pool, data);
    }

    function emergencyConfigureLossLiquidator(address pool, bytes calldata data)
        external
        override
        onlyEmergencyAdmin
        onlyRegisteredMarket(pool)
    {
        _emergencyConfigure(_getLossLiquidatorFactory(pool), pool, data);
    }

    function _deployLossLiquidator(address pool, DeployParams calldata params)
        internal
        returns (address lossLiquidator)
    {
        address factory = _getLatestLossLiquidatorFactory();
        DeployResult memory deployResult = ILossLiquidatorFactory(factory).deployLossLiquidator(pool, params);
        _executeHook(factory, deployResult.onInstallOps);
        lossLiquidator = deployResult.newContract;
        _setLossLiquidatorFactory(pool, factory);
    }

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function grantRole(bytes32 role, address account) external override onlyOwner {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external override onlyOwner {
        _revokeRole(role, account);
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function addToAccessList(address target, address factory) external override onlySelf {
        if (accessList[target] != address(0)) revert ContractAlreadyInAccessListException(target);
        accessList[target] = factory;
        _authorizedTargets[factory].add(target);
    }

    function removeFromAccessList(address target, address factory) external override onlySelf {
        _authorizedTargets[factory].remove(target);
        accessList[target] = address(0);
    }

    function migrateAccessList(address newFactory, address oldFactory)
        external
        override
        onlyMarketConfiguratorFactory
    {
        uint256 numTargets = _authorizedTargets[oldFactory].length();
        for (uint256 i; i < numTargets; ++i) {
            address target = _authorizedTargets[oldFactory].at(i);
            _authorizedTargets[oldFactory].remove(target);
            _authorizedTargets[newFactory].add(target);
            accessList[target] = newFactory;
        }
    }

    function migrate(address newMarketConfigurator) external override onlyMarketConfiguratorFactory {
        _migrate(newMarketConfigurator);
    }

    function rescue(Call[] memory calls) external override onlyMarketConfiguratorFactory {
        uint256 numCalls = calls.length;
        for (uint256 i; i < numCalls; ++i) {
            calls[i].target.functionCall(calls[i].callData);
        }
    }

    // --------- //
    // INTERNALS //
    // --------- //

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
    function _registerMarket(address pool, address priceOracle, address lossLiquidator) internal virtual {
        ContractsRegister(contractsRegister).registerMarket(pool, priceOracle, lossLiquidator);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function _registerCreditSuite(address creditManager) internal virtual {
        ContractsRegister(contractsRegister).registerCreditSuite(creditManager);
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
    function _migrate(address newMarketConfigurator) internal virtual {
        ACL(acl).transferOwnership(newMarketConfigurator);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional checks, hence the `virtual` modifier
    function _validateCallTarget(address target, address factory) internal virtual {
        if (target != address(this) && target != marketConfiguratorFactory && accessList[target] != factory) {
            revert ContractNotAssignedToFactoryException(target);
        }
    }

    function _executeMarketHooks(address pool, bytes memory data) internal {
        address[5] memory factories = [
            _getPoolFactory(pool),
            _getPriceOracleFactory(pool),
            _getInterestRateModelFactory(pool),
            _getRateKeeperFactory(pool),
            _getLossLiquidatorFactory(pool)
        ];
        for (uint256 i; i < 5; ++i) {
            _executeHook(factories[i], data);
        }
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

    function _creditManagers() internal view returns (address[] memory) {
        return ContractsRegister(contractsRegister).getCreditManagers();
    }

    function _creditManagers(address pool) internal view returns (address[] memory creditManagers) {
        return ContractsRegister(contractsRegister).getCreditManagers(pool);
    }

    function _quotaKeeper(address pool) internal view returns (address) {
        return IPoolV3(pool).poolQuotaKeeper();
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
