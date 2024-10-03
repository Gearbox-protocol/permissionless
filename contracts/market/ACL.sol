// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Holdings, 2024
pragma solidity ^0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IACLExt} from "../interfaces/extensions/IACLExt.sol";
import {AP_ACL} from "../libraries/ContractLiterals.sol";

/// @title Access control list
contract ACL is IACLExt, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_ACL;

    /// @dev Set of pausable admins
    EnumerableSet.AddressSet internal _pausableAdminsSet;

    /// @dev Set of unpausable admins
    EnumerableSet.AddressSet internal _unpausableAdminsSet;

    /// @notice Returns configurator
    /// @dev New in version `3_10`
    function getConfigurator() external view override returns (address) {
        return owner();
    }

    /// @notice Whether `account` is configurator
    function isConfigurator(address account) external view override returns (bool) {
        return account == owner();
    }

    /// @notice Returns the list of pausable admins
    /// @dev New in version `3_10`
    function getPausableAdmins() external view override returns (address[] memory) {
        return _pausableAdminsSet.values();
    }

    /// @notice Whether `account` is one of pausable admins
    function isPausableAdmin(address account) external view override returns (bool) {
        return _pausableAdminsSet.contains(account);
    }

    /// @notice Returns the list of unpausable admins
    /// @dev New in version `3_10`
    function getUnpausableAdmins() external view override returns (address[] memory) {
        return _unpausableAdminsSet.values();
    }

    /// @notice Whether `account` is one of unpausable admins
    function isUnpausableAdmin(address account) external view override returns (bool) {
        return _unpausableAdminsSet.contains(account);
    }

    /// @notice Adds `admin` to the set of pausable admins
    /// @dev Reverts if caller is not configurator
    function addPausableAdmin(address admin) external override onlyOwner {
        if (_pausableAdminsSet.add(admin)) emit AddPausableAdmin(admin);
    }

    /// @notice Removes `admin` from the set of pausable admins
    /// @dev Reverts if caller is not configurator
    function removePausableAdmin(address admin) external override onlyOwner {
        if (_pausableAdminsSet.remove(admin)) emit RemovePausableAdmin(admin);
    }

    /// @notice Adds `admin` to the set of unpausable admins
    /// @dev Reverts if caller is not configurator
    function addUnpausableAdmin(address admin) external override onlyOwner {
        if (_unpausableAdminsSet.add(admin)) emit AddUnpausableAdmin(admin);
    }

    /// @notice Removes `admin` from the set of unpausable admins
    /// @dev Reverts if caller is not configurator
    function removeUnpausableAdmin(address admin) external override onlyOwner {
        if (_unpausableAdminsSet.remove(admin)) emit RemoveUnpausableAdmin(admin);
    }
}
