// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Holdings, 2022
pragma solidity ^0.8.10;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IACL} from "@gearbox-protocol/core-v3/contracts/interfaces/IACL.sol";

/// @title ACL contract that stores admin addresses
/// More info: https://dev.gearbox.fi/security/roles
contract ACL {
    using EnumerableSet for EnumerableSet.AddressSet;

    // address public immutable acl = address(this);
    // EnumerableSet.AddressSet internal _pausableAdminSet;
    // EnumerableSet.AddressSet internal _unpausableAdminSet;

    // /// @dev Adds an address to the set of admins that can pause contracts
    // /// @param admin Address of a new pausable admin
    // function _addPausableAdmin(address admin) internal {
    //     if (!_pausableAdminSet.contains(admin)) {
    //         _pausableAdminSet.add(admin); // T:[ACL-2]
    //         emit PausableAdminAdded(admin); // T:[ACL-2]
    //     }
    // }

    // /// @dev Removes an address from the set of admins that can pause contracts
    // /// @param admin Address of admin to be removed
    // function removePausableAdmin(address admin) internal {
    //     if (!_pausableAdminSet.contains(admin)) {
    //         revert AddressNotPausableAdminException(admin);
    //     }
    //     _pausableAdminSet.remove(admin); // T:[ACL-3]
    //     emit PausableAdminRemoved(admin); // T:[ACL-3]
    // }

    // /// @dev Returns true if the address is a pausable admin and false if not
    // /// @param addr Address to check
    // function isPausableAdmin(address addr) external view returns (bool) {
    //     return _pausableAdminSet.contains(addr); // T:[ACL-2,3]
    // }

    // /// @dev Adds unpausable admin address to the list
    // /// @param admin Address of new unpausable admin
    // function _addUnpausableAdmin(address admin) internal {
    //     if (_unpausableAdminSet.contains(admin)) {
    //         _unpausableAdminSet.add(admin); // T:[ACL-4]
    //         emit UnpausableAdminAdded(admin); // T:[ACL-4]
    //     }
    // }

    // /// @dev Adds an address to the set of admins that can unpause contracts
    // /// @param admin Address of admin to be removed
    // function _removeUnpausableAdmin(address admin) internal {
    //     if (!_unpausableAdminSet.contains(admin)) {
    //         revert AddressNotUnpausableAdminException(admin);
    //     }
    //     _unpausableAdminSet.remove(admin); // T:[ACL-5]
    //     emit UnpausableAdminRemoved(admin); // T:[ACL-5]
    // }

    // /// @dev Returns true if the address is unpausable admin and false if not
    // /// @param addr Address to check
    // function isUnpausableAdmin(address addr) external view returns (bool) {
    //     return _unpausableAdminSet.contains(addr); // T:[ACL-4,5]
    // }

    // /// @dev Returns true if an address has configurator rights
    // /// @param account Address to check
    // function isConfigurator(address account) external view returns (bool) {
    //     return account = address(this); // T:[ACL-6]
    // }

    // function owner() public view override(IACL, Ownable) returns (address) {
    //     return address(this);
    // }
}
