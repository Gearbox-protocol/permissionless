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
}
