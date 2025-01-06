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

import {LibString} from "@solady/utils/LibString.sol";
import {EIP712Mainnet} from "../helpers/EIP712Mainnet.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SignatureMultisig is EIP712Mainnet, Ownable, IVersion, ReentrancyGuard {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using LibString for bytes32;
    using LibString for string;
    using LibString for uint256;

    /// @notice Meta info about contract type & version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = "SIGNATURE_MULTISIG";

    // EIP-712 type hash for Proposal only
    bytes32 public constant CROSS_CHAIN_CALL_TYPEHASH =
        keccak256("CrossChainCall(uint256 chainId,address target,bytes callData)");
    bytes32 public constant PROPOSAL_TYPEHASH = keccak256("Proposal(bytes32 proposalHash,bytes32 prevHash)");

    uint8 public confirmationThreshold;
    bytes32 public lastProposalHash;

    EnumerableSet.AddressSet internal _signers;

    bytes32[] public executedProposalHashes;

    mapping(bytes32 => EnumerableSet.Bytes32Set) internal proposalHashes;
    mapping(bytes32 => SignedProposal) public signedProposals;

    // Events
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event ConfirmationThresholdSet(uint8 newconfirmationThreshold);

    event ProposalSubmitted(bytes32 indexed proposalHash);
    event ProposalSigned(bytes32 indexed proposalHash, address indexed signer);
    event ProposalExecuted(bytes32 indexed proposalHash);
    // Errors

    error InvalidconfirmationThresholdException();
    error AlreadySignedException();

    error InvalidPrevHashException();
    error ProposalDoesNotExistException();
    error SignerAlreadyExistsException();
    error SignerDoesNotExistException();
    error InvalidconfirmationThresholdValueException();
    error MaxSignersTooLowException();
    error CallExecutionFailedException();
    error ProposalExpiredException();
    error CantBeExecutedOnCurrentChainException();
    error OnlySelfException();
    error NoCallsInProposalException();
    error NotEnoughSignaturesException();
    error InconsistentSelfCallOnOtherChainException();
    error InvalidConfirmationThresholdValueException();

    modifier onlyOnMainnet() {
        if (block.chainid != 1) revert CantBeExecutedOnCurrentChainException();
        _;
    }

    modifier onlyOnNotMainnet() {
        if (block.chainid == 1) revert CantBeExecutedOnCurrentChainException();
        _;
    }

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelfException();
        _;
    }

    // It's deployed with the same set of parameters on all chains, so it's qddress should be the same
    // @param: initialSigners - Array of initial signers
    // @param: _confirmationThreshold - Confirmation threshold
    // @param: _owner - Owner of the contract. used on Mainnet only, however, it should be same on all chains
    // to make CREATE2 address the same on all chains
    constructor(address[] memory initialSigners, uint8 _confirmationThreshold, address _owner)
        EIP712Mainnet(contractType.fromSmallString(), version.toString())
        Ownable()
    {
        uint256 len = initialSigners.length;

        for (uint256 i = 0; i < len; ++i) {
            _addSigner(initialSigners[i]);
        }

        _setConfirmationThreshold(_confirmationThreshold);
        _transferOwnership(_owner);
    }

    // @dev: Submit a new proposal
    // Executed by Gearbox DAO on Mainnet
    // @param: calls - Array of CrossChainCall structs
    // @param: prevHash - Hash of the previous proposal (zero if first proposal)
    function submitProposal(CrossChainCall[] calldata calls, bytes32 prevHash)
        external
        onlyOwner
        onlyOnMainnet
        nonReentrant
    {
        _verifyProposal({calls: calls, prevHash: prevHash});

        bytes32 proposalHash = _hashProposal({calls: calls, prevHash: prevHash});

        // Copy proposal to storage
        SignedProposal storage signedProposal = signedProposals[proposalHash];

        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            signedProposal.calls.push(calls[i]);
        }
        signedProposal.prevHash = prevHash;

        proposalHashes[lastProposalHash].add(proposalHash);

        emit ProposalSubmitted(proposalHash);
    }

    // @dev: Sign a proposal
    // Executed by any signer to make cross-chain distribution possible
    // @param: proposalHash - Hash of the proposal to sign
    // @param: signature - Signature of the proposal
    function signProposal(bytes32 proposalHash, bytes calldata signature) external onlyOnMainnet nonReentrant {
        address signer = ECDSA.recover(proposalHash, signature);
        if (!_signers.contains(signer)) revert SignerDoesNotExistException();

        SignedProposal storage signedProposal = signedProposals[proposalHash];
        if (signedProposal.prevHash != lastProposalHash) {
            revert InvalidPrevHashException();
        }

        signedProposal.signatures.push(signature);

        uint256 validSignatures = _verifySignatures({signatures: signedProposal.signatures, proposalHash: proposalHash});

        emit ProposalSigned(proposalHash, signer);

        if (validSignatures >= confirmationThreshold) {
            _verifyProposal({calls: signedProposal.calls, prevHash: signedProposal.prevHash});
            _executeProposal({calls: signedProposal.calls, proposalHash: proposalHash});
        }
    }

    // @dev: Execute a proposal on other chain permissionlessly
    function executeProposal(SignedProposal calldata signedProposal) external onlyOnNotMainnet nonReentrant {
        bytes32 proposalHash = _hashProposal(signedProposal.calls, signedProposal.prevHash);

        // Check proposal is valid
        _verifyProposal({calls: signedProposal.calls, prevHash: signedProposal.prevHash});

        // Check if enough signatures are valid
        uint256 validSignatures = _verifySignatures({signatures: signedProposal.signatures, proposalHash: proposalHash});
        if (validSignatures < confirmationThreshold) revert NotEnoughSignaturesException();

        _executeProposal({calls: signedProposal.calls, proposalHash: proposalHash});
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function _verifyProposal(CrossChainCall[] memory calls, bytes32 prevHash) internal view {
        if (prevHash != lastProposalHash) revert InvalidPrevHashException();
        if (calls.length == 0) revert NoCallsInProposalException();

        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            CrossChainCall memory call = calls[i];
            if (call.chainId != 0 && call.target == address(this)) {
                revert InconsistentSelfCallOnOtherChainException();
            }
        }
    }

    function _verifySignatures(bytes[] memory signatures, bytes32 proposalHash)
        internal
        view
        returns (uint256 validSignatures)
    {
        address[] memory proposalSigners = new address[](signatures.length);
        // Check for duplicate signatures
        uint256 len = signatures.length;
        for (uint256 i = 0; i < len; ++i) {
            address signer = ECDSA.recover(proposalHash, signatures[i]);

            // It's not reverted to avoid the case, when 2 proposals are submitted
            // and the first one is about removing a signer. The signer could add his signature
            // to the second proposal (it's still possible) and lock the system forever
            if (_signers.contains(signer)) {
                validSignatures++;
            }
            for (uint256 j = 0; j < i; ++j) {
                if (proposalSigners[j] == signer) {
                    revert AlreadySignedException();
                }
            }
            proposalSigners[i] = signer;
        }
    }

    function _executeProposal(CrossChainCall[] memory calls, bytes32 proposalHash) internal {
        // Execute each call in the proposal
        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            CrossChainCall memory call = calls[i];
            uint256 chainId = call.chainId;

            if (chainId == 0 || chainId == block.chainid) {
                // QUESTION: any security concerns?
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
        if (!_signers.add(newSigner)) revert SignerAlreadyExistsException();
        emit SignerAdded(newSigner);
    }

    function removeSigner(address signer) external onlySelf {
        if (!_signers.remove(signer)) revert SignerDoesNotExistException();
        emit SignerRemoved(signer);
    }

    function setConfirmationThreshold(uint8 newConfirmationThreshold) external onlySelf {
        _setConfirmationThreshold(newConfirmationThreshold);
    }

    function _setConfirmationThreshold(uint8 newConfirmationThreshold) internal {
        if (newConfirmationThreshold == 0 || newConfirmationThreshold > _signers.length()) {
            revert InvalidConfirmationThresholdValueException();
        }
        confirmationThreshold = newConfirmationThreshold;
        emit ConfirmationThresholdSet(newConfirmationThreshold);
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

    function getCurrentProposals() external view returns (SignedProposal[] memory result) {
        uint256 len = proposalHashes[lastProposalHash].length();
        result = new SignedProposal[](len);
        for (uint256 i = 0; i < len; ++i) {
            result[i] = signedProposals[proposalHashes[lastProposalHash].at(i)];
        }
    }
}
