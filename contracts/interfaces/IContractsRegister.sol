// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IVersion} from "@gearbox-protocol/core-v2/contracts/interfaces/IVersion.sol";

/// @title Contracts register interface
interface IContractsRegister is IVersion {
    function isPool(address) external view returns (bool);
    function isCreditManager(address) external view returns (bool);
    function getPools() external view returns (address[] memory);
    function getCreditManagers() external view returns (address[] memory);
    function addPool(address) external;
    function addCreditManager(address) external;
    function removePool(address) external;
    function removeCreditManager(address) external;
}
