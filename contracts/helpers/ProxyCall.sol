// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/// @title ProxyCall
/// @notice Contract that allows an immutable owner to make calls on its behalf
contract ProxyCall {
    using Address for address;

    /// @notice Custom errors
    error NotOwnerException();

    /// @notice The immutable owner address that can make calls through this proxy
    address public immutable owner;

    /// @notice Emitted when a call is made through the proxy
    event ProxyCallExecuted(address target, bytes data);

    /// @notice Sets the immutable owner address
    constructor() {
        owner = msg.sender;
    }

    /// @notice Modifier to restrict access to owner only
    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwnerException();
        _;
    }

    /// @notice Makes a call to target contract with provided data
    /// @param target Address of contract to call
    /// @param data Call data to execute
    /// @return success Whether the call was successful
    /// @return result The raw return data from the call
    function proxyCall(address target, bytes calldata data)
        external
        onlyOwner
        returns (bool success, bytes memory result)
    {
        // Make the call using OpenZeppelin's Address library
        return (true, target.functionCall(data));
    }
}
