// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";

contract DefaultLossPolicy is ACLTrait {
    uint256 public constant version = 3_10;
    bytes32 public constant contractType = "LOSS_POLICY::DEFAULT";

    bool public enabled;

    constructor(address acl_) ACLTrait(acl_) {}

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
