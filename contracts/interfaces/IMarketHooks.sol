// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Call} from "./Types.sol";

// TODO: consider moving to libraries/Hook.sol

/// @notice Interface for market hooks
/// @dev These hooks are called by the MarketConfigurator during various configuration events
/// Each hook returns an array of Call structs, allowing for flexible actions to be executed
/// Actions are executed by the MarketConfigurator on behalf of configurator role.
interface IMarketHooks {
    //
    // MARKET
    //
    // QUESTION: should we have it here?
    function onCreateMarket(address pool, address priceOracle) external returns (Call[] memory calls);

    /// @notice Hook that executes when a market is removed
    /// @param pool The address of the pool (represents market) being removed
    /// @return calls An array of Call structs to be executed
    function onShutdownMarket(address pool) external returns (Call[] memory calls);

    /// @notice Hook that executes when a new token is added to the market
    /// @param pool The address of the pool (represents market)
    /// @param token The address of the token being added
    /// @param priceFeed The address of the price feed for the token
    /// @return calls An array of Call structs to be executed
    function onAddToken(address pool, address token, address priceFeed) external returns (Call[] memory calls);

    /// @notice Hook that executes when the interest model is updated
    /// @param pool The address of the pool (represents market)
    /// @param newModel The address of the new interest model
    /// @return calls An array of Call structs to be executed
    function onUpdateInterestRateModel(address pool, address newModel) external returns (Call[] memory calls);

    function onUpdateRateKeeper(address pool, address newKeeper) external returns (Call[] memory calls);

    function onRemoveRateKeeper(address pool, address newKeeper) external returns (Call[] memory calls);

    //
    // CREDIT MANAGER
    //

    /// @notice Hook that executes when a new credit manager is added
    /// @param newCreditManager The address of the new credit manager
    /// @return calls An array of Call structs to be executed
    function onCreateCreditSuite(address pool, address newCreditManager) external returns (Call[] memory calls);

    /// @notice Hook that executes when a credit manager is shut down
    /// @param _creditManager The address of the credit manager being removed
    /// @return calls An array of Call structs to be executed
    function onShutdownCreditSuite(address pool, address _creditManager) external returns (Call[] memory calls);

    //
    // PRICE ORACLE
    //

    /// @notice Hook that executes when the price oracle is updated
    /// @param pool The address of the pool (represents market)
    /// @param priceOracle The address of the new price oracle
    /// @param prevOracle The address of the previous price oracle
    /// @return calls An array of Call structs to be executed
    function onUpdatePriceOracle(address pool, address priceOracle, address prevOracle)
        external
        returns (Call[] memory calls);

    /// @notice Hook that executes when a price feed is set for a token
    /// @param pool The address of the pool (represents market)
    /// @param token The address of the token
    /// @param priceFeed The address of the price feed being set
    /// @return calls An array of Call structs to be executed
    function onSetPriceFeed(address pool, address token, address priceFeed) external returns (Call[] memory calls);

    /// @notice Hook that executes when a reserve price feed is set for a token
    /// @param pool The address of the pool (represents market)
    /// @param token The address of the token
    /// @param priceFeed The address of the reserve price feed being set
    /// @return calls An array of Call structs to be executed
    function onSetReservePriceFeed(address pool, address token, address priceFeed)
        external
        returns (Call[] memory calls);
}
