// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

contract SignatureHelper is Test {
    function _generatePrivateKey(string memory salt) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(salt)));
    }

    function _sign(uint256 privateKey, bytes32 bytecodeHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, bytecodeHash);
        return abi.encodePacked(r, s, v);
    }
}
