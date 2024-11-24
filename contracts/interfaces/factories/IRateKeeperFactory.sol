// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {DeployParams, DeployResult} from "../Types.sol";
import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";
import {IMarketHooks} from "./IMarketHooks.sol";

interface IRateKeeperFactory is IVersion, IMarketHooks, IConfiguratingFactory {
    function deployRateKeeper(address pool, DeployParams calldata params) external returns (DeployResult memory);
}
