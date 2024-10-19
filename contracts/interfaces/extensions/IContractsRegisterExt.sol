// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IContractsRegister} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IContractsRegister.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IContractsRegisterExt is IContractsRegister, IVersion {
    event AddPool(address indexed pool);
    event RemovePool(address indexed pool);
    event AddCreditManager(address indexed creditManager);
    event RemoveCreditManager(address indexed creditManager);

    function addPool(address pool) external;
    function removePool(address pool) external;
    function addCreditManager(address creditManager) external;
    function removeCreditManager(address creditManager) external;

    function getCreditManagersByPool(address pool) external view returns (address[] memory);

    function getPriceOracle(address pool) external view returns (address);

    // Factories
    function getPoolFactory(address pool) external view returns (address);
    function getCreditManagerFactory(address creditManager) external view returns (address);
    function getPriceOracleFactory(address pool) external view returns (address);
    function getRateKeeperFactory(address pool) external view returns (address);
    function getInterestRateModelFactory(address model) external view returns (address);

    function setPoolFactory(address pool, address factory) external;
    function setCreditManagerFactory(address creditManager, address factory) external;
    function setPriceOracleFactory(address pool, address factory) external;

    function getRateKeeperFactory(address pool) external view returns (address);
    function getInterestRateModelFactory(address model) external view returns (address);
    function setRateKeeperFactory(address pool, address factory) external;
    function setInterestRateModelFactory(address model, address factory) external;
}
