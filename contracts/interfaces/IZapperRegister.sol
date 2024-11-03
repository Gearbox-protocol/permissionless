// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IZapperRegister is IVersion {
    function zappers(address pool) external view returns (address[] memory);
    function isZapper(address pool, address zapper) external view returns (bool);
    function addZapper(address pool, bytes32 postfix, bytes calldata params) external;
    function removeZapper(address zapper) external;
}
