// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IACL as IACLBase} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IACL.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IACL is IACLBase, IVersion {
    event AddPausableAdmin(address indexed admin);
    event RemovePausableAdmin(address indexed admin);
    event AddUnpausableAdmin(address indexed admin);
    event RemoveUnpausableAdmin(address indexed admin);
    event AddEmergencyLiquidator(address indexed liquidator);
    event RemoveEmergencyLiquidator(address indexed liquidator);

    function getConfigurator() external view returns (address);

    function getPausableAdmins() external view returns (address[] memory);
    function addPausableAdmin(address admin) external;
    function removePausableAdmin(address admin) external;

    function getUnpausableAdmins() external view returns (address[] memory);
    function addUnpausableAdmin(address admin) external;
    function removeUnpausableAdmin(address admin) external;

    function getEmergencyLiquidators() external view returns (address[] memory);
    function isEmergencyLiquidator(address account) external view returns (bool);
    function addEmergencyLiquidator(address liquidator) external;
    function removeEmergencyLiquidator(address liquidator) external;
}
