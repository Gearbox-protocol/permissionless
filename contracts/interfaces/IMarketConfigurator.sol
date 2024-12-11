// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {Call, DeployParams} from "./Types.sol";

interface IMarketConfigurator is IVersion {
    // ------ //
    // ERRORS //
    // ------ //

    error CallerIsNotSelfException();

    error CallerIsNotEmergencyAdminException();

    error CallerIsNotMarketConfiguratorFactoryException();

    error ContractNotAssignedToFactoryException(address);

    error ContractAlreadyInAccessListException(address);

    error MarketNotRegisteredException(address pool);

    error CreditSuiteNotRegisteredException(address creditManager);

    function contractName() external view returns (string memory);
    function marketConfiguratorFactory() external view returns (address);
    function acl() external view returns (address);
    function contractsRegister() external view returns (address);
    function treasury() external view returns (address);

    function emergencyAdmin() external view returns (address);

    function accessList(address target) external view returns (address factory);

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
    ) external returns (address pool);

    function shutdownMarket(address pool) external;

    function addToken(address pool, address token, address priceFeed) external;

    function configurePool(address pool, bytes calldata data) external;

    function emergencyConfigurePool(address pool, bytes calldata data) external;

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    function createCreditSuite(address pool, bytes calldata encdodedParams) external returns (address creditManager);

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

    // -–------------------------ //
    // LOSS LIQUIDATOR MANAGEMENT //
    // -–------------------------ //

    function updateLossLiquidator(address pool, DeployParams calldata params)
        external
        returns (address lossLiqudiator);

    function configureLossLiquidator(address pool, bytes calldata data) external;

    function emergencyConfigureLossLiquidator(address pool, bytes calldata data) external;

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function grantRole(bytes32 role, address account) external;

    function revokeRole(bytes32 role, address account) external;

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function addToAccessList(address target, address factory) external;

    function migrate(address newMarketConfigurator) external;

    function rescue(Call[] memory calls) external;
}
