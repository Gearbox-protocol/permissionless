// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";
import {ICreditSuiteHooks} from "./ICreditSuiteHooks.sol";
import {DeployResult} from "./Types.sol";

interface ICreditFactory is ICreditSuiteHooks, IConfiguratingFactory {
    function deployCreditSuite(address pool, bytes calldata encodedParams) external returns (DeployResult memory);
}
