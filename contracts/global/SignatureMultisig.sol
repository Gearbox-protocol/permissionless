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
import {SignatureMultisigExec} from "./SignatureMultisigExec.sol";

contract SignatureMultisig is SignatureMultisigExec {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event ProposalSubmitted(bytes32 indexed proposalHash, string cmd, bytes cmdData);
    event ProposalSigned(bytes32 indexed proposalHash, address indexed signer);

    // Store all proposals
    bytes32[] public proposalHashes;
    mapping(bytes32 => SignedProposal) public signedProposals;

    error ProposalExpired();

    constructor(address[] memory initialSigners, uint128 _threshold, uint128 _maxSigners)
        SignatureMultisigExec(initialSigners, _threshold, _maxSigners)
    {}

    function submitProposal(Proposal calldata proposal, bytes calldata signature) external {
        bytes32 proposalHash = _hashProposal(proposal);

        signedProposals[proposalHash] = SignedProposal({proposal: proposal, signatures: new bytes[](0)});
        proposalHashes.push(proposalHash);

        emit ProposalSubmitted(proposalHash, proposal.cmd, proposal.cmdData);

        _processSignature(proposalHash, signedProposals[proposalHash], signature);
    }

    function signProposal(bytes32 proposalHash, bytes calldata signature) external {
        SignedProposal storage signedProposal = signedProposals[proposalHash];

        _processSignature(proposalHash, signedProposal, signature);
    }

    function _processSignature(bytes32 proposalHash, SignedProposal storage signedProposal, bytes calldata signature)
        internal
    {
        if (signedProposal.proposal.deadline < block.timestamp) revert ProposalExpired();
        if (signedProposal.proposal.prevHash != lastProposalHash) revert InvalidPrevHash();

        address signer = ECDSA.recover(proposalHash, signature);
        if (!_signers.contains(signer)) revert NotASignerException();

        // Check for duplicate signatures
        for (uint256 i = 0; i < signedProposal.signatures.length; i++) {
            if (ECDSA.recover(proposalHash, signedProposal.signatures[i]) == signer) {
                revert AlreadySigned();
            }
        }

        signedProposal.signatures.push(signature);
        emit ProposalSigned(proposalHash, signer);

        if (signedProposal.signatures.length >= threshold) {
            _executeProposal(signedProposal, proposalHash);
        }
    }

    function parseCommand(bytes32 cmd, bytes32 data) internal virtual {
        // if (cmd == CMD_ADD_SIGNER) {
        //     return abi.decode(abi.encodePacked(data), (UpdateAddressData)).account;
        // }
    }
}
