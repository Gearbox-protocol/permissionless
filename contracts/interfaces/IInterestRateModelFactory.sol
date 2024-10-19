// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IConfigurableFactory} from "./IConfigurableFactory.sol";
import {ICreditHooks} from "./ICreditHooks.sol";
import {DeployResult} from "./Types.sol";

interface IInterestRateModelFactory is IConfigurableFactory {
    function deployInterestRateModel(bytes32 postfix, bytes calldata encodedParams)
        external
        returns (DeployResult memory);
}
