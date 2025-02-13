// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {SignedBatch, CrossChainCall} from "../interfaces/ICrossChainMultisig.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

import {LibString} from "@solady/utils/LibString.sol";
import {EIP712Mainnet} from "../helpers/EIP712Mainnet.sol";

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {ICrossChainMultisig} from "../interfaces/ICrossChainMultisig.sol";

import {AP_CROSS_CHAIN_MULTISIG} from "../libraries/ContractLiterals.sol";

contract CrossChainMultisig is EIP712Mainnet, Ownable, ReentrancyGuard, ICrossChainMultisig {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using LibString for bytes32;
    using LibString for string;
    using LibString for uint256;

    /// @notice Meta info about contract type & version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_CROSS_CHAIN_MULTISIG;

    // EIP-712 type hash for Proposal only
    bytes32 public constant CROSS_CHAIN_CALL_TYPEHASH =
        keccak256("CrossChainCall(uint256 chainId,address target,bytes callData)");
    bytes32 public constant BATCH_TYPEHASH = keccak256("Batch(string name,bytes32 batchHash,bytes32 prevHash)");

    uint8 public confirmationThreshold;

    bytes32 public lastBatchHash;

    EnumerableSet.AddressSet internal _signers;

    bytes32[] internal _executedBatchHashes;

    mapping(bytes32 => EnumerableSet.Bytes32Set) internal _connectedBatchHashes;
    mapping(bytes32 => SignedBatch) internal _signedBatches;

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
            _addSigner(initialSigners[i]); // U:[SM-1]
        }

        _setConfirmationThreshold(_confirmationThreshold); // U:[SM-1]
        _transferOwnership(_owner); // U:[SM-1]
    }

    // @dev: Submit a new proposal
    // Executed by Gearbox DAO on Mainnet
    // @param: calls - Array of CrossChainCall structs
    // @param: prevHash - Hash of the previous proposal (zero if first proposal)
    function submitBatch(string calldata name, CrossChainCall[] calldata calls, bytes32 prevHash)
        external
        onlyOwner
        onlyOnMainnet
        nonReentrant
    {
        _verifyBatch({calls: calls, prevHash: prevHash});

        bytes32 batchHash = hashBatch({name: name, calls: calls, prevHash: prevHash});

        // Copy batch to storage
        SignedBatch storage signedBatch = _signedBatches[batchHash];

        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            signedBatch.calls.push(calls[i]);
        }
        signedBatch.prevHash = prevHash;
        signedBatch.name = name;

        _connectedBatchHashes[lastBatchHash].add(batchHash);

        emit SubmitBatch(batchHash);
    }

    // @dev: Sign a proposal
    // Executed by any signer to make cross-chain distribution possible
    // @param: proposalHash - Hash of the proposal to sign
    // @param: signature - Signature of the proposal
    function signBatch(bytes32 batchHash, bytes calldata signature) external onlyOnMainnet nonReentrant {
        SignedBatch storage signedBatch = _signedBatches[batchHash];
        if (signedBatch.prevHash != lastBatchHash) {
            revert InvalidPrevHashException();
        }
        bytes32 digest = _hashTypedDataV4(computeSignBatchHash(signedBatch.name, batchHash, signedBatch.prevHash));

        address signer = ECDSA.recover(digest, signature);
        if (!_signers.contains(signer)) revert SignerDoesNotExistException();

        signedBatch.signatures.push(signature);

        uint256 validSignatures = _verifySignatures({signatures: signedBatch.signatures, digest: digest});

        emit SignBatch(batchHash, signer);

        if (validSignatures >= confirmationThreshold) {
            _verifyBatch({calls: signedBatch.calls, prevHash: signedBatch.prevHash});
            _executeBatch({calls: signedBatch.calls, batchHash: batchHash});
        }
    }

    // @dev: Execute a proposal on other chain permissionlessly
    function executeBatch(SignedBatch calldata signedBatch) external onlyOnNotMainnet nonReentrant {
        bytes32 batchHash = hashBatch(signedBatch.name, signedBatch.calls, signedBatch.prevHash);

        // Check batch is valid
        _verifyBatch({calls: signedBatch.calls, prevHash: signedBatch.prevHash});

        bytes32 digest = _hashTypedDataV4(computeSignBatchHash(signedBatch.name, batchHash, signedBatch.prevHash));

        uint256 validSignatures = _verifySignatures({signatures: signedBatch.signatures, digest: digest});
        if (validSignatures < confirmationThreshold) revert NotEnoughSignaturesException();

        _executeBatch({calls: signedBatch.calls, batchHash: batchHash});
    }

    function _verifyBatch(CrossChainCall[] memory calls, bytes32 prevHash) internal view {
        if (prevHash != lastBatchHash) revert InvalidPrevHashException();
        if (calls.length == 0) revert NoCallsInProposalException();

        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            CrossChainCall memory call = calls[i];
            if (call.chainId != 0 && call.target == address(this)) {
                revert InconsistentSelfCallOnOtherChainException();
            }
        }
    }

    function _verifySignatures(bytes[] memory signatures, bytes32 digest)
        internal
        view
        returns (uint256 validSignatures)
    {
        address[] memory proposalSigners = new address[](signatures.length);
        // Check for duplicate signatures
        uint256 len = signatures.length;

        for (uint256 i = 0; i < len; ++i) {
            address signer = ECDSA.recover(digest, signatures[i]);

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

    // @dev: Execute proposal calls and update state
    // @param: calls - Array of cross-chain calls to execute
    // @param: proposalHash - Hash of the proposal being executed
    function _executeBatch(CrossChainCall[] memory calls, bytes32 batchHash) internal {
        // Execute each call in the batch
        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            CrossChainCall memory call = calls[i];
            uint256 chainId = call.chainId;

            if (chainId == 0 || chainId == block.chainid) {
                // QUESTION: add try{} catch{} to achieve 100% execution
                Address.functionCall(call.target, call.callData, "Call execution failed");
            }
        }

        _executedBatchHashes.push(batchHash);
        lastBatchHash = batchHash;

        emit ExecuteBatch(batchHash);
    }

    //
    // MULTISIG CONFIGURATION FUNCTIONS
    //

    // @notice: Add a new signer to the multisig
    // @param: newSigner - Address of the new signer
    function addSigner(address newSigner) external onlySelf {
        _addSigner(newSigner);
    }

    function _addSigner(address newSigner) internal {
        if (!_signers.add(newSigner)) revert SignerAlreadyExistsException();
        emit AddSigner(newSigner);
    }

    // @notice: Remove a signer from the multisig
    // @param: signer - Address of the signer to remove
    function removeSigner(address signer) external onlySelf {
        if (!_signers.remove(signer)) revert SignerDoesNotExistException();
        emit RemoveSigner(signer);
    }

    // @notice: Set the confirmation threshold for the multisig
    // @param: newConfirmationThreshold - New confirmation threshold
    function setConfirmationThreshold(uint8 newConfirmationThreshold) external onlySelf {
        _setConfirmationThreshold(newConfirmationThreshold);
    }

    function _setConfirmationThreshold(uint8 newConfirmationThreshold) internal {
        if (newConfirmationThreshold == 0 || newConfirmationThreshold > _signers.length()) {
            revert InvalidConfirmationThresholdValueException();
        }
        confirmationThreshold = newConfirmationThreshold; // U:[SM-1]
        emit SetConfirmationThreshold(newConfirmationThreshold); // U:[SM-1]
    }

    //
    // HELPERS
    //
    function hashBatch(string calldata name, CrossChainCall[] calldata calls, bytes32 prevHash)
        public
        pure
        returns (bytes32)
    {
        bytes32[] memory callsHash = new bytes32[](calls.length);
        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            CrossChainCall memory call = calls[i];
            callsHash[i] = keccak256(abi.encode(CROSS_CHAIN_CALL_TYPEHASH, call.chainId, call.target, call.callData));
        }

        return keccak256(abi.encode(keccak256(bytes(name)), keccak256(abi.encodePacked(callsHash)), prevHash));
    }

    function computeSignBatchHash(string memory name, bytes32 batchHash, bytes32 prevHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(BATCH_TYPEHASH, keccak256(bytes(name)), batchHash, prevHash));
    }

    //
    // GETTERS
    //
    function getSigners() external view returns (address[] memory) {
        return _signers.values();
    }

    function getBatch(bytes32 batchHash) external view returns (SignedBatch memory result) {
        return _signedBatches[batchHash];
    }

    function getCurrentBatchHashes() external view returns (bytes32[] memory) {
        return _connectedBatchHashes[lastBatchHash].values();
    }

    function getExecutedBatchHashes() external view returns (bytes32[] memory) {
        return _executedBatchHashes;
    }

    function isSigner(address account) external view returns (bool) {
        return _signers.contains(account);
    }

    function domainSeparatorV4() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
