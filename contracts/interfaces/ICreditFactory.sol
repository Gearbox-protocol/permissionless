// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IModularFactory} from "./IModularFactory.sol";

interface ICreditFactory is IModularFactory {
    function createCreditSuite(address pool, bytes calldata encodedParams) external returns (address);
}
