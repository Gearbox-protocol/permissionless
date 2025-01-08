// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {BytecodeRepository} from "../../global/BytecodeRepository.sol";
import {IBytecodeRepository} from "../../interfaces/IBytecodeRepository.sol";
import {Bytecode, AuditorSignature} from "../../interfaces/Types.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {MockedVersionContract} from "../mocks/MockedVersionContract.sol";

contract BytecodeRepositoryTest is Test {
    using LibString for bytes32;
    using ECDSA for bytes32;

    BytecodeRepository public repository;
    address public owner;
    address public auditor;
    address public author;

    uint256 public authorPK = vm.randomUint();

    bytes32 private constant _TEST_CONTRACT = "TEST_CONTRACT";
    uint256 private constant _TEST_VERSION = 310;
    string private constant _TEST_SOURCE = "ipfs://test";
    bytes32 private constant _TEST_SALT = bytes32(uint256(1));

    function setUp() public {
        owner = makeAddr("owner");
        auditor = makeAddr("auditor");
        author = vm.addr(authorPK);

        vm.startPrank(owner);
        repository = new BytecodeRepository();
        repository.addAuditor(auditor, "Test Auditor");
        vm.stopPrank();
    }

    function _getMockBytecode(bytes32 _contractType, uint256 _version) internal pure returns (bytes memory) {
        return abi.encodePacked(type(MockedVersionContract).creationCode, abi.encode(_contractType, _version));
    }
}
