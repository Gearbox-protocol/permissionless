// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {
    Proposal,
    SignedProposal,
    UpdateAddressData,
    SetThresholdData,
    SystemContractData,
    ForbidBytecodeData,
    AddAuditorData,
    CMD_ADD_SIGNER,
    CMD_REMOVE_SIGNER,
    CMD_SET_THRESHOLD,
    CMD_SUBMIT_SYSTEM_BYTECODE,
    CMD_FORBID_BYTECODE,
    CMD_ADD_AUDITOR,
    CMD_REMOVE_AUDITOR
} from "../interfaces/ISignatureMulstig.sol";

contract SignatureMultisigExec is EIP712 {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // EIP-712 type hash for Proposal only
    bytes32 private constant PROPOSAL_TYPEHASH =
        keccak256("Proposal(string cmd,bytes32 prevHash,uint256 deadline,bytes32 cmdData)");

    uint128 public maxSigners;
    uint128 public threshold;

    // Change to private + getter / setter
    EnumerableSet.AddressSet internal _signers;
    bytes32 public lastProposalHash;

    // Replace array and mapping with EnumerableSet
    EnumerableSet.Bytes32Set private _executedProposals;

    // Add new events
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdUpdated(uint256 newThreshold);

    // Add new errors
    error InvalidThreshold();
    error TooManySigners();
    error NotEnoughSigners();
    error InvalidCommand();
    error AlreadySigned();
    error NotASignerException();
    error InvalidPrevHash();
    error ProposalDoesNotExist();

    constructor(address[] memory initialSigners, uint128 _threshold, uint128 _maxSigners)
        EIP712("SignatureMultisig", "1.0.0")
    {
        require(initialSigners.length <= _maxSigners, "Too many initial signers");
        require(_threshold <= _maxSigners, "Threshold must be less than or equal to max signers");
        maxSigners = _maxSigners;
        threshold = _threshold;

        for (uint256 i = 0; i < initialSigners.length; i++) {
            _addSigner(initialSigners[i]);
        }
    }

    function _hashProposal(Proposal calldata proposal) internal view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    PROPOSAL_TYPEHASH,
                    keccak256(bytes(proposal.cmd)),
                    proposal.prevHash,
                    proposal.deadline,
                    proposal.cmdData
                )
            )
        );
    }

    function __verifyProposal(SignedProposal calldata signedProposal, bytes32 proposalHash) internal view {
        if (signedProposal.proposal.prevHash != lastProposalHash) revert InvalidPrevHash();

        // bytes32 proposalHash = _hashProposal(signedProposal.proposal);

        address[] memory proposalSigners = new address[](signedProposal.signatures.length);
        // Check for duplicate signatures
        for (uint256 i = 0; i < signedProposal.signatures.length; ++i) {
            address signer = ECDSA.recover(proposalHash, signedProposal.signatures[i]);
            if (!_signers.contains(signer)) revert NotASignerException();

            for (uint256 j = 0; j < i; j++) {
                if (proposalSigners[j] == signer) {
                    revert AlreadySigned();
                }
            }
            proposalSigners[i] = signer;
        }
    }

    /// @notice Returns the domain separator used in the encoding of the signatures
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _executeProposal(SignedProposal memory signedProposal, bytes32 proposalHash) internal {
        lastProposalHash = proposalHash;

        // Convert command string to bytes32 using fromSmallString
        bytes32 cmd = LibString.toSmallString(signedProposal.proposal.cmd);
        bytes memory data = signedProposal.proposal.cmdData;

        // Execute based on command using direct bytes32 comparison
        if (cmd == CMD_ADD_SIGNER) {
            if (_signers.length() >= maxSigners) revert TooManySigners();
            UpdateAddressData memory updateData = abi.decode(abi.encodePacked(data), (UpdateAddressData));
            _addSigner(updateData.addr);
        } else if (cmd == CMD_REMOVE_SIGNER) {
            if (_signers.length() <= threshold) revert NotEnoughSigners();
            UpdateAddressData memory updateData = abi.decode(abi.encodePacked(data), (UpdateAddressData));
            _removeSigner(updateData.addr);
        } else if (cmd == CMD_SET_THRESHOLD) {
            SetThresholdData memory thresholdData = abi.decode(abi.encodePacked(data), (SetThresholdData));
            if (thresholdData.threshold == 0 || thresholdData.threshold > _signers.length()) {
                revert InvalidThreshold();
            }
            threshold = thresholdData.threshold;
            emit ThresholdUpdated(thresholdData.threshold);
        } else {
            _parseCommand(cmd, data);
        }
        // else if (cmd == CMD_SUBMIT_SYSTEM) {
        //     SystemContractData memory systemData = abi.decode(abi.encodePacked(data), (SystemContractData));
        //     require(_auditors.contains(systemData.auditor), "Not an auditor");
        //     emit SystemContractSubmitted(systemData.bytecodeHash, systemData.auditor, systemData.executionTime);
        // } else if (cmd == CMD_FORBID_BYTECODE) {
        //     ForbidBytecodeData memory forbidData = abi.decode(abi.encodePacked(data), (ForbidBytecodeData));
        //     forbiddenBytecodes[forbidData.bytecodeHash] = true;
        //     emit BytecodeForbidden(forbidData.bytecodeHash);
        // } else if (cmd == CMD_ADD_AUDITOR) {
        //     AddAuditorData memory auditorData = abi.decode(abi.encodePacked(data), (AddAuditorData));
        //     require(_auditors.add(auditorData.account), "Auditor already exists");
        //     emit AuditorAdded(auditorData.account);
        // } else if (cmd == CMD_REMOVE_AUDITOR) {
        //     AddAuditorData memory auditorData = abi.decode(abi.encodePacked(data), (AddAuditorData));
        //     require(_auditors.remove(auditorData.account), "Auditor does not exist");
        //     emit AuditorRemoved(auditorData.account);
        // }
        // else {
        //     revert InvalidCommand();
        // }
        _executedProposals.add(proposalHash);
    }

    function _addSigner(address newSigner) internal {
        require(_signers.add(newSigner), "Signer already exists");
        emit SignerAdded(newSigner);
    }

    function _removeSigner(address signer) internal {
        require(_signers.remove(signer), "Signer does not exist");
        emit SignerRemoved(signer);
    }

    function _parseCommand(bytes32 cmd, bytes memory data) internal virtual {
        revert InvalidCommand();
    }

    function isExecuted(bytes32 proposalHash) public view returns (bool) {
        return _executedProposals.contains(proposalHash);
    }

    function getExecutedProposals() external view returns (bytes32[] memory) {
        return _executedProposals.values();
    }

    function getExecutedProposalCount() external view returns (uint256) {
        return _executedProposals.length();
    }
}
