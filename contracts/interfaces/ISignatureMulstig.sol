// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

// Commands
// ADD_SIGNER - Add singer
// input: UpdateAddressProposal
// REMOVE_SIGNER - Remove singer
// input: UpdateAddressProposal
// SET_THRESHOLD - Set threshold
// input: SetThresholdProposal
// SUBMIT_SYSTEM_BYTECODE - Submit SYSTEM contract bytecode
// input: SystemContractProposal
// FORBID_BYTECODE - Remove and forbid bytecode
// input: ForbidBytecodeProposal
// ADD_AUDITOR - Add auditor
// input: AddAuditorProposal
// REMOVE_AUDITOR - Remove auditor
// input: UpdateAddressProposal

bytes32 constant CMD_ADD_SIGNER = "ADD_SIGNER";
bytes32 constant CMD_REMOVE_SIGNER = "REMOVE_SIGNER";
bytes32 constant CMD_SET_THRESHOLD = "SET_THRESHOLD";
bytes32 constant CMD_SUBMIT_SYSTEM_BYTECODE = "SUBMIT_SYSTEM_BYTECODE";
bytes32 constant CMD_FORBID_BYTECODE = "FORBID_BYTECODE";
bytes32 constant CMD_ADD_AUDITOR = "ADD_AUDITOR";
bytes32 constant CMD_REMOVE_AUDITOR = "REMOVE_AUDITOR";

struct Proposal {
    string cmd;
    bytes cmdData;
    bytes32 prevHash;
    uint256 deadline;
}

struct SignedProposal {
    Proposal proposal;
    bytes[] signatures;
}

struct UpdateAddressData {
    address addr;
}

struct SetThresholdData {
    uint128 threshold;
}

struct SystemContractData {
    bytes32 bytecodeHash;
    bytes32 contractName;
    bytes32 contractVersion;
    address auditor;
    uint256 executionTime;
}

struct ForbidBytecodeData {
    bytes32 bytecodeHash;
}

struct AddAuditorData {
    address addr;
    string name;
}
