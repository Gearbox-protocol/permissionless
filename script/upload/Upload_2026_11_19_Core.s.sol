// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {CreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/credit/CreditFacadeV3.sol";

import {Bytecode} from "../../contracts/interfaces/Types.sol";
import {UploadBytecode} from "../UploadBytecode.sol";

contract Upload_2026_11_19_Core is UploadBytecode {
    function _getContracts() internal pure override returns (Bytecode[] memory bytecodes) {
        bytecodes = new Bytecode[](1);
        bytecodes[0].contractType = "CREDIT_FACADE";
        bytecodes[0].version = 3_11;
        bytecodes[0].initCode = type(CreditFacadeV3).creationCode;
        bytecodes[0].source =
            "https://github.com/Gearbox-protocol/core-v3/blob/ae03efa578ec45feca4a5e5829873cfec503f09e/contracts/credit/CreditFacadeV3.sol";
    }
}
