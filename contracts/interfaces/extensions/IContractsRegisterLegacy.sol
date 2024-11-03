// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IContractsRegister as IContractsRegisterBase} from
    "@gearbox-protocol/core-v3/contracts/interfaces/base/IContractsRegister.sol";

interface IContractsRegisterLegacy is IContractsRegisterBase {
    function addPool(address pool) external;
    function addCreditManager(address creditManager) external;
}
