// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";

import {IContractsRegisterExt} from "../interfaces/extensions/IContractsRegisterExt.sol";
import {AP_CONTRACTS_REGISTER} from "../libraries/ContractLiterals.sol";

/// @title Contracts register
contract ContractsRegister is ACLTrait, IContractsRegisterExt {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_CONTRACTS_REGISTER;

    /// @dev Set of registered pools
    EnumerableSet.AddressSet internal _poolsSet;

    /// @dev Set of registered credit managers
    EnumerableSet.AddressSet internal _creditManagersSet;

    /// @notice Constructor
    /// @param acl_ ACL contract address
    constructor(address acl_) ACLTrait(acl_) {}

    /// @notice Returns the list of registered pools
    function getPools() external view override returns (address[] memory) {
        return _poolsSet.values();
    }

    /// @notice Whether `pool` is one of registered pools
    function isPool(address pool) external view override returns (bool) {
        return _poolsSet.contains(pool);
    }

    /// @notice Returns the list of registered credit managers
    function getCreditManagers() external view override returns (address[] memory) {
        return _creditManagersSet.values();
    }

    /// @notice Whether `creditManager` is one of registered credit managers
    function isCreditManager(address creditManager) external view returns (bool) {
        return _creditManagersSet.contains(creditManager);
    }

    /// @notice Adds `pool` to the set of registered pools
    /// @dev Reverts if caller is not configurator
    function addPool(address pool) external override configuratorOnly {
        // idea: check that pool's contract register is `address(this)`?
        if (_poolsSet.add(pool)) emit AddPool(pool);
    }

    /// @notice Removes `pool` from the set of registered pools
    /// @dev Reverts if caller is not configurator
    /// @dev New in version `3_10`
    function removePool(address pool) external override configuratorOnly {
        if (_poolsSet.remove(pool)) emit RemovePool(pool);
    }

    /// @notice Adds `creditManager` to the set of registered credit managers
    /// @dev Reverts if caller is not configurator
    function addCreditManager(address creditManager) external override configuratorOnly {
        // idea: check that credit manager's pool is registered? add a getter that returns credit managers by pool?
        if (_creditManagersSet.add(creditManager)) emit AddCreditManager(creditManager);
    }

    /// @notice Removes `creditManager` from the set of registered credit managers
    /// @dev Reverts if caller is not configurator
    /// @dev New in version `3_10`
    function removeCreditManager(address creditManager) external override configuratorOnly {
        if (_creditManagersSet.remove(creditManager)) emit RemoveCreditManager(creditManager);
    }

    //
    function getCreditManagersByPool(address pool) external view returns (address[] memory) {}

    function getPriceOracle(address pool) external view returns (address) {}

    // Factories
    function getPoolFactory(address pool) external view returns (address) {}
    function getCreditManagerFactory(address creditManager) external view returns (address) {}
    function getPriceOracleFactory(address pool) external view returns (address) {}

    function setPoolFactory(address pool, address factory) external {}
    function setCreditManagerFactory(address creditManager, address factory) external {}
    function setPriceOracleFactory(address pool, address factory) external {}

    function getRateKeeperFactory(address pool) external view returns (address) {}
    function getInterestRateModelFactory(address model) external view returns (address) {}
    function setRateKeeperFactory(address pool, address factory) external {}
    function setInterestRateModelFactory(address model, address factory) external {}
}
