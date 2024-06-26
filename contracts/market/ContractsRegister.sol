// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";
import {IContractsRegister} from "../interfaces/IContractsRegister.sol";

contract ContractsRegister is ACLTrait, IContractsRegister {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    EnumerableSet.AddressSet internal _pools;
    EnumerableSet.AddressSet internal _creditManagers;

    constructor(address _acl) ACLTrait(_acl) {}

    function addPool(address pool) external override configuratorOnly {
        _pools.add(pool);
    }

    function removePool(address pool) external override configuratorOnly {
        _pools.remove(pool);
    }

    function addCreditManager(address creditManager) external override configuratorOnly {
        _creditManagers.add(creditManager);
    }

    function removeCreditManager(address creditManager) external override configuratorOnly {
        _creditManagers.remove(creditManager);
    }

    /// @dev Returns the array of registered pools
    function getPools() external view returns (address[] memory) {
        return _pools.values();
    }

    /// @dev Returns true if the passed address is a pool
    function isPool(address pool) external view returns (bool) {
        return _pools.contains(pool);
    }

    /// @dev Returns the array of registered Credit Managers
    function getCreditManagers() external view returns (address[] memory) {
        return _creditManagers.values();
    }

    /// @dev Returns true if the passed address is a Credit Manager
    function isCreditManager(address creditManager) external view returns (bool) {
        return _creditManagers.contains(creditManager);
    }
}
