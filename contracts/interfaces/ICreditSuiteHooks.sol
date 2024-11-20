// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Call} from "./Types.sol";

// QUESTION: I really doubt this architecture
// onUpdatePriceOracle and onUpdateLossLiquidator are market hooks -- why do we have them
// {add|remove}EmergencyLiqudiator are hardcoded functions, why use hooks at all

interface ICreditSuiteHooks {
    /// @notice Hook that executes when the price oracle is updated for a credit manager
    /// @param creditManager The address of the credit manager being updated
    /// @param newPriceOracle The address of the new price oracle
    /// @param oldPriceOracle The address of the previous price oracle
    /// @return calls An array of Call structs representing actions to be executed
    function onUpdatePriceOracle(address creditManager, address newPriceOracle, address oldPriceOracle)
        external
        returns (Call[] memory calls);

    function onUpdateLossLiquidator(address creditManager, address newLossLiquidator, address oldLossLiquidator)
        external
        returns (Call[] memory calls);

    function onAddEmergencyLiquidator(address creditManager, address emergencyLiquidator)
        external
        returns (Call[] memory calls);

    function onRemoveEmergencyLiquidator(address creditManager, address emergencyLiquidator)
        external
        returns (Call[] memory calls);
}
