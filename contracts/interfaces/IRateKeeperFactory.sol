// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IConfigurableFactory} from "./IConfigurableFactory.sol";
import {Call, DeployResult} from "./Types.sol";

interface IRateKeeperFactory is IConfigurableFactory {
    function deployRateKeeper(address pool, bytes32 rateKeeperPostfix, bytes calldata encodedParams)
        external
        returns (DeployResult memory);
}
