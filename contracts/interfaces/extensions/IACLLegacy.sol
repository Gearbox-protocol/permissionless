// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IACL as IACLBase} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IACL.sol";

interface IACLLegacy is IACLBase {
    function owner() external;
    function pendingOwner() external view returns (address);
    function transferOwnership(address newOwner) external;
    function claimOwnership() external;

    function addPausableAdmin(address admin) external;
    function removePausableAdmin(address admin) external;

    function addUnpausableAdmin(address admin) external;
    function removeUnpausableAdmin(address admin) external;
}
