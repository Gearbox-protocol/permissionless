// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IACLTrait} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IACLTrait.sol";
import {IContractsRegister as IContractsRegisterBase} from
    "@gearbox-protocol/core-v3/contracts/interfaces/base/IContractsRegister.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IContractsRegister is IContractsRegisterBase, IVersion, IACLTrait {
    // ------ //
    // EVENTS //
    // ------ //

    event CreateMarket(address indexed pool, address indexed priceOracle, address indexed lossLiquidator);
    event ShutdownMarket(address indexed pool);
    event CreateCreditSuite(address indexed pool, address indexed creditManager);
    event ShutdownCreditSuite(address indexed creditManager);
    event SetPriceOracle(address indexed pool, address indexed priceOracle);
    event SetLossLiquidator(address indexed pool, address indexed lossLiquidator);

    // ------ //
    // ERRORS //
    // ------ //

    error MarketNotRegisteredException(address pool);
    error MarketShutDownException(address pool);
    error MarketNotEmptyException(address pool);
    error CreditSuiteNotRegisteredException(address creditManager);
    error CreditSuiteShutDownException(address creditManager);
    error CreditSuiteMisconfiguredException(address creditManager);

    // ------- //
    // MARKETS //
    // ------- //

    function getShutdownPools() external view returns (address[] memory);
    function getPriceOracle(address pool) external view returns (address);
    function getLossLiquidator(address pool) external view returns (address);

    function createMarket(address pool, address priceOracle, address lossLiquidator) external;
    function shutdownMarket(address pool) external;
    function setPriceOracle(address pool, address priceOracle) external;
    function setLossLiquidator(address pool, address lossLiquidator) external;

    // ------------- //
    // CREDIT SUITES //
    // ------------- //

    function getCreditManagers(address pool) external view returns (address[] memory);
    function getShutdownCreditManagers() external view returns (address[] memory);
    function getShutdownCreditManagers(address pool) external view returns (address[] memory);

    function createCreditSuite(address pool, address creditManager) external;
    function shutdownCreditSuite(address creditManager) external;
}
