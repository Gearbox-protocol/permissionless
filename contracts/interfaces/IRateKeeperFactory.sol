// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IModularFactory} from "./IModularFactory.sol";
import {Call} from "./Types.sol";

interface IRateKeeperFactory is IModularFactory {
    function deployRateKeeper(address pool, bytes32 rateKeeperPostfix, bytes calldata encodedParams)
        external
        returns (address rateKeeper, Call[] memory onInstallOps);
}
