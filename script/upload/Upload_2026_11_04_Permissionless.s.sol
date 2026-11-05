// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {KillSwitchProxyCall} from "../../contracts/helpers/KillSwitchProxy.sol";
import {Bytecode} from "../../contracts/interfaces/Types.sol";
import {UploadBytecode} from "../UploadBytecode.sol";

contract Upload_2026_11_04_Permissionless is UploadBytecode {
    function _getContracts() internal pure override returns (Bytecode[] memory bytecodes) {
        bytecodes = new Bytecode[](1);
        bytecodes[0].contractType = "KILL_SWITCH_PROXY";
        bytecodes[0].version = 3_10;
        bytecodes[0].initCode = type(KillSwitchProxyCall).creationCode;
        bytecodes[0].source =
            "https://github.com/Gearbox-protocol/permissionless/blob/12fec541c297c18387331ee3817a38da0ae0e03d/contracts/helpers/KillSwitchProxy.sol";
    }
}
