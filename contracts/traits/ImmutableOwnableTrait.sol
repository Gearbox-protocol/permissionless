// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IImmutableOwnable} from "../interfaces/IImmutableIOwnable.sol";

/// @title ImmutableOwnableTrait
/// @notice Contract that adds immutable owner functionality when inherited
abstract contract ImmutableOwnableTrait is IImmutableOwnable {
    /// @notice Custom errors
    error NotOwnerException();

    /// @notice The immutable owner address
    address public immutable override owner;

    /// @notice Sets the immutable owner address
    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Modifier to restrict access to owner only
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwnerException();
        _;
    }
}
