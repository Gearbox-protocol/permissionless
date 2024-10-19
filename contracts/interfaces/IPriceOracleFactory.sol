// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IConfigurableFactory} from "./IConfigurableFactory.sol";
import {ICreditHooks} from "./ICreditHooks.sol";
import {DeployResult} from "./Types.sol";

// QUESTION: is it configurable factory?
interface IPriceOracleFactory is IConfigurableFactory {
    function deployPriceOracle(bytes calldata constructorParams) external returns (DeployResult memory);
}
