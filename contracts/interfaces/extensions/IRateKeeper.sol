// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IRateKeeper as IRateKeeperBase} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IRateKeeper.sol";

interface IRateKeeper is IRateKeeperBase {
    function addToken(address token) external;
}
