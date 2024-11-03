// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";
import {ICreditHooks} from "./ICreditHooks.sol";
import {DeployResult} from "./Types.sol";

interface IInterestRateModelFactory is IConfiguratingFactory {
    function deployInterestRateModel(bytes32 postfix, bytes calldata encodedParams)
        external
        returns (DeployResult memory);
}
