// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {ILossPolicy} from "@gearbox-protocol/core-v3/contracts/interfaces/base/ILossPolicy.sol";

contract MockLossPolicy is ILossPolicy {
    uint256 public constant version = 3_10;
    bytes32 public constant contractType = "LOSS_POLICY::MOCK";

    bool public enabled;

    constructor(address pool, address addressProvider) {}

    function serialize() external pure override returns (bytes memory) {}

    function isLiquidatable(address, address, bytes calldata) external view returns (bool) {
        return enabled;
    }

    function enable() external {
        enabled = true;
    }

    function disable() external {
        enabled = false;
    }
}
