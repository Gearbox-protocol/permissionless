// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {ACLNonReentrantTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLNonReentrantTrait.sol";
import {PERCENTAGE_FACTOR} from "@gearbox-protocol/core-v2/contracts/libraries/Constants.sol";

struct Policy {
    bool enabled;
    address admin;
    uint40 delay;
    bool checkInterval;
    bool checkSet;
    uint256 intervalMinValue;
    uint256 intervalMaxValue;
    uint256[] setValues;
}

/// @title Policy manager V3
/// @dev A contract for managing bounds and conditions for mission-critical protocol params
abstract contract PolicyManagerV3 is ACLNonReentrantTrait {
    /// @dev Mapping from group-derived key to policy
    mapping(string => Policy) internal _policies;

    /// @notice Emitted when new policy is set
    event SetPolicy(string indexed policyID, bool enabled);

    constructor(address _acl) ACLNonReentrantTrait(_acl) {}

    /// @notice Sets the params for a new or existing policy, using policy UID as key
    /// @param policyID A unique identifier for a policy, generally, should be the signature of a method which uses the policy.
    ///                 Can also in some cases need additional parameters to be concatenated
    /// @param policyParams Policy parameters
    function setPolicy(string calldata policyID, Policy memory policyParams)
        external
        configuratorOnly // U:[PM-1]
    {
        policyParams.enabled = true; // U:[PM-1]
        _policies[policyID] = policyParams; // U:[PM-1]
        emit SetPolicy({policyID: policyID, enabled: true}); // U:[PM-1]
    }

    /// @notice Disables the policy which makes all requested checks for the passed policy hash to auto-fail
    /// @param policyID A unique identifier for a policy
    function disablePolicy(string calldata policyID)
        public
        configuratorOnly // U:[PM-2]
    {
        _policies[policyID].enabled = false; // U:[PM-2]
        emit SetPolicy({policyID: policyID, enabled: false}); // U:[PM-2]
    }

    /// @notice Retrieves policy from policy UID
    function getPolicy(string calldata policyID) external view returns (Policy memory) {
        return _policies[policyID]; // U:[PM-1]
    }

    /// @dev Returns policy transaction delay, with policy retrieved based on contract and parameter name
    function _getPolicyDelay(string memory policyID) internal view returns (uint256) {
        return _policies[policyID].delay;
    }

    /// @dev Performs parameter checks, with policy retrieved based on policy UID
    function _checkPolicy(string memory policyID, uint256 newValue) internal returns (bool) {
        Policy storage policy = _policies[policyID];

        if (!policy.enabled) return false; // U:[PM-2]

        if (policy.admin != msg.sender) return false; // U: [PM-5]

        if (policy.checkInterval) {
            if (newValue < policy.intervalMinValue || newValue > policy.intervalMaxValue) return false; // U: [PM-3]
        }

        if (policy.checkSet) {
            if (!_isIn(policy.setValues, newValue)) return false; // U: [PM-4]
        }

        return true;
    }

    /// @dev Returns whether the value is an element of `arr`
    function _isIn(uint256[] memory arr, uint256 value) internal pure returns (bool) {
        uint256 len = arr.length;

        for (uint256 i = 0; i < len;) {
            if (value == arr[i]) return true;

            unchecked {
                ++i;
            }
        }

        return false;
    }
}
