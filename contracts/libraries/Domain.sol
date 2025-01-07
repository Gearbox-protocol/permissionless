// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {AP_INSTANCE_MANAGER} from "./ContractLiterals.sol";
import {LibString} from "@solady/utils/LibString.sol";

library Domain {
    using LibString for string;

    function extractDomain(string memory str) internal pure returns (string memory) {
        uint256 underscoreIndex = str.indexOf("::");

        // If no underscore found, treat the whole name as domain
        if (underscoreIndex == LibString.NOT_FOUND) {
            return "";
        }

        return str.slice(0, underscoreIndex);
    }
}
