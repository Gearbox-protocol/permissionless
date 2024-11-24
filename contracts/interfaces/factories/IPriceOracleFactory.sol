// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {DeployResult} from "../Types.sol";
import {IMarketHooks} from "./IMarketHooks.sol";

interface IPriceOracleFactory is IVersion, IMarketHooks {
    function deployPriceOracle(address pool) external returns (DeployResult memory);
}
