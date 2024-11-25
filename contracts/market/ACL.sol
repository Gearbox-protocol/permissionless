// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Holdings, 2024
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IACL} from "../interfaces/extensions/IACL.sol";
import {AP_ACL, ROLE_PAUSABLE_ADMIN, ROLE_UNPAUSABLE_ADMIN} from "../libraries/ContractLiterals.sol";

/// @title Access control list
contract ACL is IACL, Ownable2Step {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_ACL;

    /// @dev Set of accounts that have been granted role `role`
    mapping(bytes32 role => EnumerableSet.AddressSet) internal _roleHolders;

    /// @notice Returns configurator
    function getConfigurator() external view override returns (address) {
        return owner();
    }

    /// @notice Whether `account` is configurator
    function isConfigurator(address account) external view override returns (bool) {
        return account == owner();
    }

    /// @notice Whether `account` is one of pausable admins
    /// @dev Exists for backward compatibility
    function isPausableAdmin(address account) external view override returns (bool) {
        return hasRole(ROLE_PAUSABLE_ADMIN, account);
    }

    /// @notice Whether `account` is one of unpausable admins
    /// @dev Exists for backward compatibility
    function isUnpausableAdmin(address account) external view override returns (bool) {
        return hasRole(ROLE_UNPAUSABLE_ADMIN, account);
    }

    /// @notice Returns the list of accounts that have been granted role `role`
    function getRoleHolders(bytes32 role) external view override returns (address[] memory) {
        return _roleHolders[role].values();
    }

    /// @notice Whether account `account` has been granted role `role`
    function hasRole(bytes32 role, address account) public view override returns (bool) {
        return _roleHolders[role].contains(account);
    }

    /// @notice Grants role `role` to account `account`
    /// @dev Reverts if caller is not configurator
    function grantRole(bytes32 role, address account) external override onlyOwner {
        if (_roleHolders[role].add(account)) emit GrantRole(role, account);
    }

    /// @notice Revokes role `role` from account `account`
    /// @dev Reverts if caller is not configurator
    function revokeRole(bytes32 role, address account) external override onlyOwner {
        if (_roleHolders[role].remove(account)) emit RevokeRole(role, account);
    }
}
