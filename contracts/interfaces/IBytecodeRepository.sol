// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IBytecodeRepository is IVersion {
    function deploy(bytes32 contractType, uint256 version, bytes memory constructorParams, bytes32 salt)
        external
        returns (address);

    function deployByDomain(
        bytes32 _domain,
        bytes32 _postfix,
        uint256 _version,
        bytes memory constructorParams,
        bytes32 salt
    ) external returns (address newContract);

    function computeAddress(bytes32 _contractType, uint256 _version, bytes memory constructorParams, bytes32 salt)
        external
        view
        returns (address);

    function getTokenSpecificPostfix(address token) external view returns (bytes32);
}
