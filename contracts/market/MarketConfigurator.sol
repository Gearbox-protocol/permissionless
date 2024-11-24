// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {LibString} from "@solady/utils/LibString.sol";

import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {
    RegisteredPoolOnlyException,
    RegisteredCreditManagerOnlyException
} from "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {IConfiguratingFactory} from "../interfaces/factories/IConfiguratingFactory.sol";
import {ICreditFactory} from "../interfaces/factories/ICreditFactory.sol";
import {IInterestRateModelFactory} from "../interfaces/factories/IInterestRateModelFactory.sol";
import {ILossLiquidatorFactory} from "../interfaces/factories/ILossLiquidatorFactory.sol";
import {IMarketHooks} from "../interfaces/factories/IMarketHooks.sol";
import {IPoolFactory} from "../interfaces/factories/IPoolFactory.sol";
import {IPriceOracleFactory} from "../interfaces/factories/IPriceOracleFactory.sol";
import {IRateKeeperFactory} from "../interfaces/factories/IRateKeeperFactory.sol";

import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {AP_MARKET_CONFIGURATOR} from "../libraries/ContractLiterals.sol";

import {ACL} from "./ACL.sol";
import {ContractsRegister} from "./ContractsRegister.sol";

// TODO:
// - factories upgradability
// - management functions (i.e., shorter timelock but less checks)

// TODO: reconsider roles (createMarket, createCreditSuite, addToken, manage... don't need long multisig,
// others do; but longer multisig should be able to call all of them)

/// @title Market configurator
contract MarketConfigurator is Ownable2Step, IMarketConfigurator {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    address public immutable override marketConfiguratorFactory;
    address public immutable override acl;
    address public immutable override contractsRegister;
    address public immutable override treasury;

    mapping(address contract_ => address factory) public accessList;

    bytes32 internal immutable _name;

    modifier onlyMarketConfiguratorFactory() {
        if (msg.sender != marketConfiguratorFactory) revert CallerIsNotMarketConfiguratorFactoryException();
        _;
    }

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    constructor(string memory name_, address marketConfiguratorFactory_, address riskCurator_, address treasury_) {
        marketConfiguratorFactory = marketConfiguratorFactory_;
        transferOwnership(riskCurator_);
        acl = address(new ACL());
        contractsRegister = address(new ContractsRegister(acl));
        treasury = treasury_;
        _name = LibString.toSmallString(name_);
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

        ContractsRegister(contractsRegister).createMarket(pool, priceOracle, lossLiquidator);
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
        ContractsRegister(contractsRegister).shutdownMarket(pool);
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

        ContractsRegister(contractsRegister).createCreditSuite(pool, creditManager);
        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onCreateCreditSuite, (pool, creditManager)));
    }

    function shutdownCreditSuite(address creditManager) external override onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        _executeMarketHooks(
            ICreditManagerV3(creditManager).pool(), abi.encodeCall(IMarketHooks.onShutdownCreditSuite, (creditManager))
        );
        ContractsRegister(contractsRegister).shutdownCreditSuite(creditManager);
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
        address oldPriceOracle = ContractsRegister(contractsRegister).getPriceOracle(pool);

        priceOracle = _deployPriceOracle(pool);

        ContractsRegister(contractsRegister).setPriceOracle(pool, priceOracle);
        _executeMarketHooks(pool, abi.encodeCall(IMarketHooks.onUpdatePriceOracle, (pool, priceOracle, oldPriceOracle)));

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
        address oldLossLiquidator = ContractsRegister(contractsRegister).getLossLiquidator(pool);

        lossLiquidator = _deployLossLiquidator(pool, params);

        ContractsRegister(contractsRegister).setLossLiquidator(pool, lossLiquidator);
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
                    ICreditFactory.onUpdateLossLiquidator, (creditManager, lossLiquidator, oldLossLiquidator)
                )
            );
        }
    }

    function configureLossLiquidator(address pool, bytes calldata data) external override onlyOwner {
        _ensureRegisteredPool(pool);
        address lossLiquidator = ContractsRegister(pool).getLossLiquidator(pool);
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

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function addPausableAdmin(address admin) public virtual override onlyOwner {
        ACL(acl).addPausableAdmin(admin);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function addUnpausableAdmin(address admin) public virtual override onlyOwner {
        ACL(acl).addUnpausableAdmin(admin);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function removePausableAdmin(address admin) public virtual override onlyOwner {
        ACL(acl).removePausableAdmin(admin);
    }

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function removeUnpausableAdmin(address admin) public virtual override onlyOwner {
        ACL(acl).removeUnpausableAdmin(admin);
    }

    function addEmergencyLiquidator(address liquidator) external override onlyOwner {
        ACL(acl).addEmergencyLiquidator(liquidator);
    }

    function removeEmergencyLiquidator(address liquidator) external override onlyOwner {
        ACL(acl).removeEmergencyLiquidator(liquidator);
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    /// @dev `MarketConfiguratorLegacy` performs additional actions, hence the `virtual` modifier
    function migrate(address newMarketConfigurator) public virtual override onlyMarketConfiguratorFactory {
        ACL(acl).transferOwnership(newMarketConfigurator);
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

    function _ensureRegisteredPool(address pool) internal view {
        if (!ContractsRegister(contractsRegister).isPool(pool)) {
            revert RegisteredPoolOnlyException();
        }
    }

    function _ensureRegisteredCreditManager(address creditManager) internal view {
        if (!ContractsRegister(contractsRegister).isCreditManager(creditManager)) {
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
            if (call.target != marketConfiguratorFactory && accessList[call.target] != factory) {
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
        return ContractsRegister(contractsRegister).getCreditManagers();
    }

    function _creditManagers(address pool) internal view returns (address[] memory creditManagers) {
        return ContractsRegister(contractsRegister).getCreditManagers(pool);
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
