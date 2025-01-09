// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {Call, DeployParams, MarketFactories} from "./Types.sol";

interface IMarketConfigurator is IVersion {
    // ------ //
    // EVENTS //
    // ------ //

    event AuthorizeFactory(address indexed factory, address indexed suite, address indexed target);

    event UnauthorizeFactory(address indexed factory, address indexed suite, address indexed target);

    // ------ //
    // ERRORS //
    // ------ //

    error CallerIsNotAdminException(address caller);

    error CallerIsNotEmergencyAdminException(address caller);

    error CallerIsNotSelfException(address caller);

    error CreditSuiteNotRegisteredException(address creditManager);

    error MarketNotRegisteredException(address pool);

    error UnauthorizedFactoryException(address factory, address target);

    // --------------- //
    // STATE VARIABLES //
    // --------------- //

    function curatorName() external view returns (string memory);

    function admin() external view returns (address);
    function emergencyAdmin() external view returns (address);

    function addressProvider() external view returns (address);
    function acl() external view returns (address);
    function contractsRegister() external view returns (address);
    function treasury() external view returns (address);

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function grantRole(bytes32 role, address account) external;

    function revokeRole(bytes32 role, address account) external;

    function emergencyRevokeRole(bytes32 role, address account) external;

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
    ) external returns (address pool);

    function shutdownMarket(address pool) external;

    function addToken(address pool, address token, address priceFeed) external;

    function configurePool(address pool, bytes calldata data) external;

    function emergencyConfigurePool(address pool, bytes calldata data) external;

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    function createCreditSuite(uint256 minorVersion, address pool, bytes calldata encdodedParams)
        external
        returns (address creditManager);

    function shutdownCreditSuite(address creditManager) external;

    function configureCreditSuite(address creditManager, bytes calldata data) external;

    function emergencyConfigureCreditSuite(address creditManager, bytes calldata data) external;

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    function updatePriceOracle(address pool) external returns (address priceOracle);

    function configurePriceOracle(address pool, bytes calldata data) external;

    function emergencyConfigurePriceOracle(address pool, bytes calldata data) external;

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function updateInterestRateModel(address pool, DeployParams calldata params) external returns (address irm);

    function configureInterestRateModel(address pool, bytes calldata data) external;

    function emergencyConfigureInterestRateModel(address pool, bytes calldata data) external;

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    function updateRateKeeper(address pool, DeployParams calldata params) external returns (address rateKeeper);

    function configureRateKeeper(address pool, bytes calldata data) external;

    function emergencyConfigureRateKeeper(address pool, bytes calldata data) external;

    // -–-------------------- //
    // LOSS POLICY MANAGEMENT //
    // -–-------------------- //

    function updateLossPolicy(address pool, DeployParams calldata params) external returns (address lossPolicy);

    function configureLossPolicy(address pool, bytes calldata data) external;

    function emergencyConfigureLossPolicy(address pool, bytes calldata data) external;

    // --------- //
    // FACTORIES //
    // --------- //

    function getMarketFactories(address pool) external view returns (MarketFactories memory);

    function getCreditFactory(address creditManager) external view returns (address);

    function getAuthorizedFactory(address target) external view returns (address);

    function getFactoryTargets(address factory, address suite) external view returns (address[] memory);

    function authorizeFactory(address factory, address suite, address target) external;

    function unauthorizeFactory(address factory, address suite, address target) external;

    function upgradePoolFactory(address pool) external;

    function upgradePriceOracleFactory(address pool) external;

    function upgradeInterestRateModelFactory(address pool) external;

    function upgradeRateKeeperFactory(address pool) external;

    function upgradeLossPolicyFactory(address pool) external;

    function upgradeCreditFactory(address creditManager) external;
}
