// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

/// @title Deployer trait interface
interface IDeployerTrait {
    function addressProvider() external view returns (address);

    function bytecodeRepository() external view returns (address);
}
