// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

interface IMarketConfiguratorFactory {
    function isMarketConfigurator(address) external view returns (bool);
    function marketConfigurators() external view returns (address[] memory);
    function createMarketConfigurator() external returns (address);
    function removeMarketConfigurator(address configurator) external;
}
