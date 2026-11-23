// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ImmutableOwnableTrait} from "../traits/ImmutableOwnableTrait.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

contract KillSwitchProxyCall is ImmutableOwnableTrait, IVersion {
    using Address for address;

    error OnlyCallerException();
    error KilledException();
    error OwnerSameAsCallerException();

    event Killed();

    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = "KILL_SWITCH_PROXY";

    bool public isKilled = false;

    address public immutable caller;

    modifier onlyCaller() {
        if (msg.sender != caller) revert OnlyCallerException();
        _;
    }

    constructor(address _owner, address _caller) ImmutableOwnableTrait(_owner) {
        if (_owner == _caller) revert OwnerSameAsCallerException();
        caller = _caller;
    }

    function proxyCall(address target, bytes calldata data) external onlyCaller returns (bytes memory result) {
        if (isKilled) revert KilledException();
        return target.functionCall(data);
    }

    function kill() external onlyOwner {
        isKilled = true;
        emit Killed();
    }
}
