// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";
import {IMarketHooks} from "./IMarketHooks.sol";
import {Call, DeployResult} from "./Types.sol";

interface IRateKeeperFactory is IMarketHooks, IConfiguratingFactory {
    function deployRateKeeper(address pool, bytes32 rateKeeperPostfix, bytes calldata encodedParams)
        external
        returns (DeployResult memory);
}
