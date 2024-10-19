// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {Call} from "./Types.sol";

interface IConfigurableFactory {
    function configure(address target, bytes calldata callData) external returns (Call[] memory calls);
}
