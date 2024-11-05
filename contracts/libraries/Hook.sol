// SPDX-License-Identifier: UNLICENSED
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {Call} from "../interfaces/Types.sol";
import {IMarketHooks} from "../interfaces/IMarketHooks.sol";
import {ICreditHooks} from "../interfaces/ICreditHooks.sol";

interface IHook {}

struct HookCheck {
    address factory;
    Call[] calls;
}

library HookExecutor {
    function onCreateMarket(IHook factory, address pool, address priceOracle) internal returns (HookCheck memory) {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onCreateMarket(pool, priceOracle)
        });
    }

    function onShutdownMarket(IHook factory, address pool) internal returns (HookCheck memory) {
        return HookCheck({factory: address(factory), calls: IMarketHooks(address(factory)).onShutdownMarket(pool)});
    }

    function onAddToken(IHook factory, address pool, address token, address priceFeed)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onAddToken(pool, token, priceFeed)
        });
    }

    function onUpdateInterestRateModel(IHook factory, address pool, address newModel)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onUpdateInterestRateModel(pool, newModel)
        });
    }

    function onUpdateRateKeeper(IHook factory, address pool, address newKeeper) internal returns (HookCheck memory) {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onUpdateRateKeeper(pool, newKeeper)
        });
    }

    function onRemoveRateKeeper(IHook factory, address pool) internal returns (HookCheck memory) {
        return HookCheck({factory: address(factory), calls: IMarketHooks(address(factory)).onRemoveRateKeeper(pool)});
    }

    function onCreateCreditSuite(IHook factory, address pool, address newCreditManager)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onCreateCreditSuite(pool, newCreditManager)
        });
    }

    function onShutdownCreditSuite(IHook factory, address pool, address _creditManager)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onShutdownCreditSuite(pool, _creditManager)
        });
    }

    function onUpdatePriceOracle(IHook factory, address pool, address priceOracle, address prevOracle)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onUpdatePriceOracle(pool, priceOracle, prevOracle)
        });
    }

    function onSetPriceFeed(IHook factory, address pool, address token, address priceFeed)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onSetPriceFeed(pool, token, priceFeed)
        });
    }

    function onSetReservePriceFeed(IHook factory, address pool, address token, address priceFeed)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: IMarketHooks(address(factory)).onSetReservePriceFeed(pool, token, priceFeed)
        });
    }

    // function onUpdatePriceOracle(IHook factory, address creditManager, address priceOracle, address prevOracle)
    //     internal
    //     returns (HookCheck memory)
    // {
    //     return HookCheck({
    //         factory: address(factory),
    //         calls: ICreditHooks(address(factory)).onUpdatePriceOracle(creditManager, priceOracle, prevOracle)
    //     });
    // }

    function onAddEmergencyLiquidator(IHook factory, address creditManager, address emergencyLiquidator)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: ICreditHooks(address(factory)).onAddEmergencyLiquidator(creditManager, emergencyLiquidator)
        });
    }

    function onRemoveEmergencyLiquidator(IHook factory, address creditManager, address emergencyLiquidator)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: ICreditHooks(address(factory)).onRemoveEmergencyLiquidator(creditManager, emergencyLiquidator)
        });
    }

    function onUpdateLossLiquidator(IHook factory, address creditManager, address lossLiquidator)
        internal
        returns (HookCheck memory)
    {
        return HookCheck({
            factory: address(factory),
            calls: ICreditHooks(address(factory)).onUpdateLossLiquidator(creditManager, lossLiquidator)
        });
    }
}
