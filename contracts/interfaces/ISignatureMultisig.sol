// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {CrossChainCall} from "./Types.sol";

struct SignedProposal {
    CrossChainCall[] calls;
    bytes32 prevHash;
    bytes[] signatures;
}
