// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Holdings, 2024
pragma solidity ^0.8.10;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IACL} from "../interfaces/IACL.sol";

import {AP_ACL} from "../libraries/ContractLiterals.sol";

/// @title ACL contract that stores admin addresses
/// More info: https://dev.gearbox.fi/security/roles
contract ACL is IACL, Ownable {
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet pausableAdminSet;
    EnumerableSet.AddressSet unpausableAdminSet;

    // Contract version
    uint256 public constant version = 3_10;
    bytes32 public constant contractType = AP_ACL;

    /// @dev Adds an address to the set of admins that can pause contracts
    /// @param admin Address of a new pausable admin
    function addPausableAdmin(address admin)
        external
        onlyOwner // T:[ACL-1]
    {
        if (pausableAdminSet.contains(admin)) {
            pausableAdminSet.add(admin); // T:[ACL-2]
            emit PausableAdminAdded(admin); // T:[ACL-2]
        }
    }

    /// @dev Removes an address from the set of admins that can pause contracts
    /// @param admin Address of admin to be removed
    function removePausableAdmin(address admin)
        external
        onlyOwner // T:[ACL-1]
    {
        if (!pausableAdminSet.contains(admin)) {
            revert AddressNotPausableAdminException(admin);
        }
        pausableAdminSet.remove(admin); // T:[ACL-3]
        emit PausableAdminRemoved(admin); // T:[ACL-3]
    }

    /// @dev Returns true if the address is a pausable admin and false if not
    /// @param admin Address to check
    function isPausableAdmin(address admin) external view override returns (bool) {
        return pausableAdminSet.contains(admin); // T:[ACL-2,3]
    }

    /// @dev Adds unpausable admin address to the list
    /// @param admin Address of new unpausable admin
    function addUnpausableAdmin(address admin)
        external
        onlyOwner // T:[ACL-1]
    {
        if (unpausableAdminSet.contains(admin)) {
            unpausableAdminSet.add(admin); // T:[ACL-2]
            emit UnpausableAdminAdded(admin); // T:[ACL-2]
        }
    }

    /// @dev Adds an address to the set of admins that can unpause contracts
    /// @param admin Address of admin to be removed
    function removeUnpausableAdmin(address admin)
        external
        onlyOwner // T:[ACL-1]
    {
        if (!unpausableAdminSet.contains(admin)) {
            revert AddressNotUnpausableAdminException(admin);
        }
        unpausableAdminSet.remove(admin); // T:[ACL-5]
        emit UnpausableAdminRemoved(admin); // T:[ACL-5]
    }

    /// @dev Returns true if the address is unpausable admin and false if not
    /// @param admin Address to check
    function isUnpausableAdmin(address admin) external view override returns (bool) {
        return unpausableAdminSet.contains(admin); // T:[ACL-4,5]
    }

    /// @dev Returns true if an address has configurator rights
    /// @param account Address to check
    function isConfigurator(address account) external view override returns (bool) {
        return account == owner(); // T:[ACL-6]
    }

    function owner() public view override(IACL, Ownable) returns (address) {
        return Ownable.owner();
    }
}
