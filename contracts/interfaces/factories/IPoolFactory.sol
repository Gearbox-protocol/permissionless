// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {DeployResult} from "../Types.sol";
import {IMarketFactory} from "./IMarketFactory.sol";

interface IPoolFactory is IMarketFactory {
    // TODO: consider adding a preview method that returns pool and quota keeper address
    // same for other factories
    function deployPool(address underlying, string calldata name, string calldata symbol)
        external
        returns (DeployResult memory);
}
