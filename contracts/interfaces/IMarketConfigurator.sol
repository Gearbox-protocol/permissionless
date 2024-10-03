// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

interface IMarketConfigurator {
    function addressProvider() external view returns (address);
    function acl() external view returns (address);
    function contractsRegister() external view returns (address);
    function treasury() external view returns (address);
}
