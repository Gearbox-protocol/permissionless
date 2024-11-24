// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {DeployResult} from "../Types.sol";
import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";
import {IMarketHooks} from "./IMarketHooks.sol";

interface IPoolFactory is IVersion, IMarketHooks, IConfiguratingFactory {
    // TODO: consider adding a preview method that returns pool and quota keeper address
    // same for other factories
    function deployPool(address underlying, string calldata name, string calldata symbol)
        external
        returns (DeployResult memory);
}
