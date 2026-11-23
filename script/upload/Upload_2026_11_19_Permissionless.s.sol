// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {SignatureDegenNFT} from "../../contracts/helpers/SignatureDegenNFT.sol";
import {Bytecode} from "../../contracts/interfaces/Types.sol";
import {UploadBytecode} from "../UploadBytecode.sol";

contract Upload_2026_11_19_Permissionless is UploadBytecode {
    function _getContracts() internal pure override returns (Bytecode[] memory bytecodes) {
        bytecodes = new Bytecode[](1);
        bytecodes[0].contractType = "DEGEN_NFT::SIGNATURE";
        bytecodes[0].version = 3_10;
        bytecodes[0].initCode = type(SignatureDegenNFT).creationCode;
        bytecodes[0].source =
            "https://github.com/Gearbox-protocol/permissionless/blob/9b74e7b8c483b8bca0b97813de899675d346006e/contracts/helpers/SignatureDegenNFT.sol";
    }
}
