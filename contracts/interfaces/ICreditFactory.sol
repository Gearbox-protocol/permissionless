// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IConfigurableFactory} from "./IConfigurableFactory.sol";
import {ICreditHooks} from "./ICreditHooks.sol";
import {DeployResult} from "./Types.sol";

interface ICreditFactory is ICreditHooks, IConfigurableFactory {
    function createCreditSuite(address pool, bytes calldata encodedParams) external returns (DeployResult memory);
}
