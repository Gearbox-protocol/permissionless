// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {ILossPolicy} from "@gearbox-protocol/core-v3/contracts/interfaces/base/ILossPolicy.sol";
import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";
import {AP_LOSS_POLICY_DEFAULT} from "../libraries/ContractLiterals.sol";

contract DefaultLossPolicy is ILossPolicy, ACLTrait {
    uint256 public constant version = 3_10;
    bytes32 public constant contractType = AP_LOSS_POLICY_DEFAULT;

    bool public enabled;

    // QUESTION: shouldn't it take pool address and AP so that it can be used with loss policy factory?
    // that would make it hard to use in legacy market configurator
    constructor(address acl_) ACLTrait(acl_) {}

    function serialize() external view override returns (bytes memory) {
        return abi.encode(enabled);
    }

    function isLiquidatable(address, address, bytes calldata) external view returns (bool) {
        return enabled;
    }

    function enable() external configuratorOnly {
        enabled = true;
    }

    function disable() external configuratorOnly {
        enabled = false;
    }
}
