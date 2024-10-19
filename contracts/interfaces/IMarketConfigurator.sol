// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

struct CreateMarketParams {
    address underlying;
    // Pool params
    string symbol;
    string name;
    bytes poolParams;
    // PriceOracle params
    address underlyingPriceFeed;
    bytes priceOracleParams;
    // InterestRateModel par
    bytes32 irmPostFix;
    bytes irmParams;
    // RateKeeper
    bytes32 rateKeeperPosfix;
    bytes rateKeeperParams;
}

interface IMarketConfigurator is IVersion {
    function configuratorFactory() external view returns (address);
    function addressProvider() external view returns (address);
    function acl() external view returns (address);
    function contractsRegister() external view returns (address);
    function treasury() external view returns (address);

    // function priceFeedStore() external view returns (address);

    function priceOracles(address pool) external view returns (address);
    // function lossLiquidators(address pool) external view returns (address);
    // function controller() external view returns (address);
    function emergencyLiquidators() external view returns (address[] memory);
}
