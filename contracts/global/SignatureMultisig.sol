// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {SignedProposal, CrossChainCall} from "../interfaces/ISignatureMultisig.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

contract SignatureMultisig is EIP712, Ownable, IVersion {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice Meta info about contract type & version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = "SIGNATURE_MULTISIG";

    // EIP-712 type hash for Proposal only
    bytes32 public constant CROSS_CHAIN_CALL_TYPEHASH =
        keccak256("CrossChainCall(uint256 chainId,address target,bytes callData)");
    bytes32 public constant PROPOSAL_TYPEHASH = keccak256("Proposal(bytes32 proposalHash,bytes32 prevHash)");

    uint128 public maxSigners;
    uint128 public threshold;

    EnumerableSet.AddressSet internal _signers;
    bytes32 public lastProposalHash;

    bytes32[] public executedProposalHashes;

    mapping(bytes32 => EnumerableSet.Bytes32Set) internal proposalHashes;
    mapping(bytes32 => SignedProposal) public signedProposals;

    // Events
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ThresholdSet(uint256 newThreshold);
    event MaxSignersSet(uint256 newMaxSigners);

    event ProposalSubmitted(bytes32 indexed proposalHash);
    event ProposalSigned(bytes32 indexed proposalHash, address indexed signer);
    event ProposalExecuted(bytes32 indexed proposalHash);
    // Errors

    error InvalidThreshold();
    error TooManySigners();
    error NotEnoughSigners();
    error InvalidCommand();
    error AlreadySigned();

    error InvalidPrevHash();
    error ProposalDoesNotExist();
    error SignerAlreadyExists();
    error SignerDoesNotExistException();
    error InvalidThresholdValue();
    error MaxSignersTooLow();
    error CallExecutionFailed();
    error ProposalExpired();
    error NotOnMainnet();
    error OnlySelfError();
    error NoCallsInProposal();
    error NotEnoughSignatures();
    error InconsistentSelfCallOnOtherChainException();

    modifier onlyOnMainnet() {
        if (block.chainid != 1) revert NotOnMainnet();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelfError();
        _;
    }

    constructor(address[] memory initialSigners, uint128 _threshold, uint128 _maxSigners, address _owner)
        EIP712("SignatureMultisig", "1.0.0")
        Ownable()
    {
        for (uint256 i = 0; i < initialSigners.length; ++i) {
            _addSigner(initialSigners[i]);
        }

        _setThreshold(_threshold);
        _setMaxSigners(_maxSigners);
        _transferOwnership(_owner);
    }

    function submitProposal(CrossChainCall[] calldata calls, bytes32 prevHash) external onlyOwner onlyOnMainnet {
        if (prevHash != lastProposalHash) revert InvalidPrevHash();

        if (calls.length == 0) revert NoCallsInProposal();

        bytes32 proposalHash = _hashProposal(calls, prevHash);
        signedProposals[proposalHash] = SignedProposal({calls: calls, prevHash: prevHash, signatures: new bytes[](0)});
        proposalHashes[lastProposalHash].add(proposalHash);

        emit ProposalSubmitted(proposalHash);
    }

    function signProposal(bytes32 proposalHash, bytes calldata signature) external onlyOnMainnet {
        address signer = ECDSA.recover(proposalHash, signature);
        if (!_signers.contains(signer)) revert SignerDoesNotExistException();

        SignedProposal storage signedProposal = signedProposals[proposalHash];
        signedProposal.signatures.push(signature);
        emit ProposalSigned(proposalHash, signer);

        _verifyProposal(signedProposal, proposalHash);

        if (signedProposal.signatures.length >= threshold) {
            _executeProposal(signedProposal, proposalHash);
        }
    }

    function executeProposal(SignedProposal calldata signedProposal) external {
        bytes32 proposalHash = _hashProposal(signedProposal.calls, signedProposal.prevHash);
        _verifyProposal(signedProposal, proposalHash);

        if (signedProposal.signatures.length < threshold) revert NotEnoughSignatures();

        _executeProposal(signedProposal, proposalHash);
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _verifyProposal(SignedProposal memory signedProposal, bytes32 proposalHash) internal view {
        if (signedProposal.prevHash != lastProposalHash) revert InvalidPrevHash();

        address[] memory proposalSigners = new address[](signedProposal.signatures.length);
        // Check for duplicate signatures
        for (uint256 i = 0; i < signedProposal.signatures.length; ++i) {
            address signer = ECDSA.recover(proposalHash, signedProposal.signatures[i]);
            if (!_signers.contains(signer)) revert SignerDoesNotExistException();

            for (uint256 j = 0; j < i; ++j) {
                if (proposalSigners[j] == signer) {
                    revert AlreadySigned();
                }
            }
            proposalSigners[i] = signer;
        }
    }

    function _executeProposal(SignedProposal memory signedProposal, bytes32 proposalHash) internal {
        if (signedProposal.prevHash != lastProposalHash) revert InvalidPrevHash();

        CrossChainCall[] memory calls = signedProposal.calls;

        uint256 len = calls.length;
        if (len == 0) revert NoCallsInProposal();

        // Execute each call in the proposal
        for (uint256 i = 0; i < len; ++i) {
            CrossChainCall memory call = calls[i];
            uint256 chainId = call.chainId;
            if (chainId != 0 && call.target == address(this)) {
                revert InconsistentSelfCallOnOtherChainException();
            }
            if (chainId == 0 || chainId == block.chainid) {
                Address.functionCall(call.target, call.callData, "Call execution failed");
            }
        }

        executedProposalHashes.push(proposalHash);
        lastProposalHash = proposalHash;

        emit ProposalExecuted(proposalHash);
    }

    //
    // MULTISIG FUNCTIONS
    //
    function addSigner(address newSigner) external onlySelf {
        _addSigner(newSigner);
    }

    function _addSigner(address newSigner) internal {
        if (!_signers.add(newSigner)) revert SignerAlreadyExists();
        emit SignerAdded(newSigner);
    }

    function removeSigner(address signer) external onlySelf {
        if (!_signers.remove(signer)) revert SignerDoesNotExistException();
        emit SignerRemoved(signer);
    }

    function setThreshold(uint128 newThreshold) external onlySelf {
        _setThreshold(newThreshold);
    }

    function _setThreshold(uint128 newThreshold) internal {
        if (newThreshold == 0 || newThreshold > _signers.length()) revert InvalidThresholdValue();
        threshold = newThreshold;
        emit ThresholdSet(newThreshold);
    }

    function setMaxSigners(uint128 newMaxSigners) external onlySelf {
        _setMaxSigners(newMaxSigners);
    }

    function _setMaxSigners(uint128 newMaxSigners) internal {
        if (newMaxSigners < _signers.length()) revert MaxSignersTooLow();
        maxSigners = newMaxSigners;
        emit MaxSignersSet(newMaxSigners);
    }

    //
    // HELPERS
    //
    function _hashCrossChainCall(CrossChainCall calldata call) internal pure returns (bytes32) {
        return keccak256(abi.encode(CROSS_CHAIN_CALL_TYPEHASH, call.chainId, call.target, call.callData));
    }

    function _hashProposal(CrossChainCall[] calldata calls, bytes32 prevHash) internal view returns (bytes32) {
        bytes32[] memory callsHash = new bytes32[](calls.length);
        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            callsHash[i] = _hashCrossChainCall(calls[i]);
        }

        return
            _hashTypedDataV4(keccak256(abi.encode(PROPOSAL_TYPEHASH, keccak256(abi.encodePacked(callsHash)), prevHash)));
    }
}
