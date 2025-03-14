// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

interface IPriceOracleEmergencyConfigureActions {
    function setPriceFeed(address token, address priceFeed) external;
}
