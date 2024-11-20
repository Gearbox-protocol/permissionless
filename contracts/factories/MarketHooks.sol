// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IMarketHooks} from "../interfaces/IMarketHooks.sol";
import {Call} from "../interfaces/Types.sol";

/// @dev Provides empty implementations of market hooks
contract MarketHooks is IMarketHooks {
    function onCreateMarket(address, address, address, address, address, address)
        external
        virtual
        returns (Call[] memory)
    {}

    function onShutdownMarket(address) external virtual returns (Call[] memory) {}

    function onCreateCreditSuite(address, address) external virtual returns (Call[] memory) {}

    function onShutdownCreditSuite(address) external virtual returns (Call[] memory) {}

    function onUpdatePriceOracle(address, address, address) external virtual returns (Call[] memory) {}

    function onUpdateInterestRateModel(address, address, address) external virtual returns (Call[] memory) {}

    function onUpdateRateKeeper(address, address, address) external virtual returns (Call[] memory) {}

    function onUpdateLossLiquidator(address, address, address) external virtual returns (Call[] memory) {}

    function onAddToken(address, address, address) external virtual returns (Call[] memory) {}

    function onSetPriceFeed(address, address, address) external virtual returns (Call[] memory) {}

    function onSetReservePriceFeed(address, address, address) external virtual returns (Call[] memory) {}
}
