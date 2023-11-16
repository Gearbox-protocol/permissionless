// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/// @title Create2 factory
/// @notice Deploys contract from bytecode and salt using create2
contract Create2Factory is Ownable {
    using Address for address;

    constructor() Ownable(msg.sender) {}

    function callExternal(address target, bytes calldata data) external onlyOwner {
        target.functionCall(data);
    }

    function callExternalWithValue(address target, bytes calldata data) external payable onlyOwner {
        target.functionCallWithValue(data, msg.value);
    }

    function deploy(bytes32 salt, bytes calldata bytecode) external onlyOwner {
        Create2.deploy(0, salt, bytecode);
    }
}
