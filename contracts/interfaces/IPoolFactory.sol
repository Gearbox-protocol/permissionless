// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";
import {IMarketHooks} from "./IMarketHooks.sol";
import {Call, DeployResult} from "./Types.sol";

interface IPoolFactory is IMarketHooks, IConfiguratingFactory {
    function deployPool(address asset, string calldata name, string calldata symbol)
        external
        returns (DeployResult memory);
}
