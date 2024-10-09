// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IContractsFactory is IVersion {
    function deployPool(
        address acl,
        address contractsRegister,
        address underlying,
        address treasury,
        address irm,
        bytes calldata params
    ) external returns (address pool, address quotaKeeper);

    // should always take latest `accountFactory` from AP
    function deployCreditManager(address pool, address priceOracle, bytes calldata params) external returns (address);

    // should take latest `botList` from AP upon initial deployment and `creditManager`'s bot list upon migration
    function deployCreditFacade(address creditManager, bytes calldata params) external returns (address);

    function deployCreditConfigurator(address creditManager, bytes calldata params) external returns (address);

    function deployPriceOracle(address acl, bytes calldata params) external returns (address);

    function deployController(address acl, bytes calldata params) external returns (address);

    function deployInterestRateModel(address acl, bytes32 type_, bytes calldata params) external returns (address);

    // should take latest `gearStaking` from AP
    function deployRateKeeper(address pool, bytes32 type_, bytes calldata params) external returns (address);

    function deployLossLiquidator(address pool, bytes32 type_, bytes calldata params) external returns (address);

    function deployPriceFeed(bytes32 type_, bytes calldata params) external returns (address);

    function deployZapper(address pool, bytes32 type_, bytes calldata params) external returns (address);

    function deployAdapter(address creditManager, address targetContract, bytes calldata params)
        external
        returns (address);
}
