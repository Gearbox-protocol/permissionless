// SPDX-License-Identifier: UNLICENSED
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {PolicyManagerV3, Policy} from "../PolicyManagerV3.sol";

contract PolicyManagerV3Harness is PolicyManagerV3 {
    constructor(address _addressProvider) PolicyManagerV3(_addressProvider) {}

    function checkPolicy(string memory policyID, uint256 newValue) external returns (bool) {
        return _checkPolicy(policyID, newValue);
    }
}
