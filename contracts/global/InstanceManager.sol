// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {SignatureMultisigExec} from "./SignatureMultisigExec.sol";
import {BytecodeRepository} from "./BytecodeRepository.sol";
import {
    SystemContractData,
    ForbidBytecodeData,
    AddAuditorData,
    CMD_SUBMIT_SYSTEM_BYTECODE,
    CMD_FORBID_BYTECODE,
    CMD_ADD_AUDITOR,
    CMD_REMOVE_AUDITOR
} from "../interfaces/ISignatureMulstig.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract InstanceManager is SignatureMultisigExec, Ownable2Step {
    BytecodeRepository public immutable bytecodeRepository;

    event SystemContractSubmitted(bytes32 indexed bytecodeHash, address indexed auditor, uint256 executionTime);
    event BytecodeForbidden(bytes32 indexed bytecodeHash);
    event AuditorAdded(address indexed account);
    event AuditorRemoved(address indexed account);

    constructor(address[] memory initialSigners, uint128 _threshold, uint128 _maxSigners)
        SignatureMultisigExec(initialSigners, _threshold, _maxSigners)
        Ownable2Step()
    {
        // Deploy BytecodeRepository and become its owner
        bytecodeRepository = new BytecodeRepository();
        // Transfer ownership of BytecodeRepository to this contract
        bytecodeRepository.transferOwnership(address(this));
    }

    function _parseCommand(bytes32 cmd, bytes memory data) internal override {
        if (cmd == CMD_SUBMIT_SYSTEM_BYTECODE) {
            SystemContractData memory systemData = abi.decode(abi.encodePacked(data), (SystemContractData));
            emit SystemContractSubmitted(systemData.bytecodeHash, systemData.auditor, systemData.executionTime);
        } else if (cmd == CMD_FORBID_BYTECODE) {
            ForbidBytecodeData memory forbidData = abi.decode(abi.encodePacked(data), (ForbidBytecodeData));
            emit BytecodeForbidden(forbidData.bytecodeHash);
        } else if (cmd == CMD_ADD_AUDITOR) {
            AddAuditorData memory auditorData = abi.decode(abi.encodePacked(data), (AddAuditorData));
            bytecodeRepository.addAuditor(auditorData.addr, auditorData.name);
            emit AuditorAdded(auditorData.addr);
        } else if (cmd == CMD_REMOVE_AUDITOR) {
            AddAuditorData memory auditorData = abi.decode(abi.encodePacked(data), (AddAuditorData));
            bytecodeRepository.forbidAuditor(auditorData.addr);
            emit AuditorRemoved(auditorData.addr);
        } else {
            revert InvalidCommand();
        }
    }
}
