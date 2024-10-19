// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IConfigurableFactory} from "./IConfigurableFactory.sol";
import {IMarketHooks} from "./IMarketHooks.sol";
import {Call, DeployResult} from "./Types.sol";

interface IPoolFactory is IMarketHooks, IConfigurableFactory {
    function deployPool(address asset, string calldata name, string calldata symbol)
        external
        returns (DeployResult memory);
}
