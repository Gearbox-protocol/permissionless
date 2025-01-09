// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

/// @title IImmutableOwnable interface
/// @notice Interface for contracts with immutable owner functionality
interface IImmutableOwnable {
    /// @notice Returns the immutable owner address
    function owner() external view returns (address);
}
