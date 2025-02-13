// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {CrossChainCall, SignedBatch, SignedRecoveryModeMessage} from "./Types.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface ICrossChainMultisig is IVersion {
    //
    // Events
    //
    /// @notice Emitted when a new signer is added to the multisig
    /// @param signer Address of the newly added signer
    event AddSigner(address indexed signer);

    /// @notice Emitted when a signer is removed from the multisig
    /// @param signer Address of the removed signer
    event RemoveSigner(address indexed signer);

    /// @notice Emitted when the confirmation threshold is updated
    /// @param newconfirmationThreshold New number of required signatures
    event SetConfirmationThreshold(uint8 newconfirmationThreshold);

    /// @notice Emitted when a new batch is submitted
    /// @param batchHash Hash of the submitted batch
    event SubmitBatch(bytes32 indexed batchHash);

    /// @notice Emitted when a signer signs a batch
    /// @param batchHash Hash of the signed batch
    /// @param signer Address of the signer
    event SignBatch(bytes32 indexed batchHash, address indexed signer);

    /// @notice Emitted when a batch is successfully executed
    /// @param batchHash Hash of the executed batch
    event ExecuteBatch(bytes32 indexed batchHash);

    /// @notice Emitted when recovery mode is enabled
    /// @param startingBatchHash Hash of the starting batch
    event EnableRecoveryMode(bytes32 indexed startingBatchHash);

    /// @notice Emitted when recovery mode is disabled
    event DisableRecoveryMode();

    // Errors

    /// @notice Thrown when an invalid confirmation threshold is set
    error InvalidconfirmationThresholdException();

    /// @notice Thrown when a signer attempts to sign a proposal multiple times
    error AlreadySignedException();

    /// @notice Thrown when the previous proposal hash doesn't match the expected value
    error InvalidPrevHashException();

    /// @notice Thrown when trying to interact with a non-existent batch
    error BatchDoesNotExistException();

    /// @notice Thrown when trying to add a signer that already exists
    error SignerAlreadyExistsException();

    /// @notice Thrown when trying to remove a non-existent signer
    error SignerDoesNotExistException();

    /// @notice Thrown when trying to execute a proposal on the wrong chain
    error CantBeExecutedOnCurrentChainException();

    /// @notice Thrown when a restricted function is called by non-multisig address
    error OnlySelfException();

    /// @notice Thrown when submitting a proposal with no calls
    error NoCallsInProposalException();

    /// @notice Thrown when trying to execute a batch with insufficient signatures
    error NotEnoughSignaturesException();

    /// @notice Thrown when self-calls are inconsistent with the target chain
    error InconsistentSelfCallOnOtherChainException();

    /// @notice Thrown when setting an invalid confirmation threshold value
    error InvalidConfirmationThresholdValueException();

    /// @notice Thrown when attempting to start recovery mode with an incorrect starting batch hash
    error InvalidRecoveryModeMessageException();

    /// @notice Submits a new batch to the multisig
    /// @param calls Array of cross-chain calls to be executed
    /// @param prevHash Hash of the previous batch (for ordering)
    function submitBatch(string calldata name, CrossChainCall[] calldata calls, bytes32 prevHash) external;

    /// @notice Allows a signer to sign a submitted batch
    /// @param batchHash Hash of the batch to sign
    /// @param signature Signature of the signer
    function signBatch(bytes32 batchHash, bytes calldata signature) external;

    /// @notice Executes a batch once it has enough signatures
    /// @param batch The signed batch to execute
    function executeBatch(SignedBatch calldata batch) external;

    /// @notice Enables recovery mode
    /// @param message Recover mode message with starting batch hash and signatures
    function enableRecoveryMode(SignedRecoveryModeMessage memory message) external;

    /// @notice Adds a new signer to the multisig
    /// @param signer Address of the signer to add
    function addSigner(address signer) external;

    /// @notice Removes a signer from the multisig
    /// @param signer Address of the signer to remove
    function removeSigner(address signer) external;

    /// @notice Sets a new confirmation threshold
    /// @param newThreshold New threshold value
    function setConfirmationThreshold(uint8 newThreshold) external;

    /// @notice Disables recovery mode
    function disableRecoveryMode() external;

    /// @notice Hashes a batch according to EIP-712
    /// @param name Name of the batch
    /// @param calls Array of cross-chain calls
    /// @param prevHash Hash of the previous batch
    /// @return bytes32 Hash of the batch
    function hashBatch(string calldata name, CrossChainCall[] calldata calls, bytes32 prevHash)
        external
        view
        returns (bytes32);

    //
    // GETTERS
    //

    /// @notice Returns the current confirmation threshold
    function confirmationThreshold() external view returns (uint8);

    /// @notice Returns the hash of the last executed batch
    function lastBatchHash() external view returns (bytes32);

    /// @notice Returns the array of executed batch hashes
    function getExecutedBatchHashes() external view returns (bytes32[] memory);

    /// @notice Returns all currently pending batches
    function getCurrentBatchHashes() external view returns (bytes32[] memory);

    /// @notice Returns a single executed batch
    function getBatch(bytes32 batchHash) external view returns (SignedBatch memory);

    /// @notice Returns the list of current signers
    function getSigners() external view returns (address[] memory);

    /// @notice Checks if an address is a signer
    /// @param account Address to check
    function isSigner(address account) external view returns (bool);

    /// @notice Returns the domain separator used for EIP-712 signing
    function domainSeparatorV4() external view returns (bytes32);
}
