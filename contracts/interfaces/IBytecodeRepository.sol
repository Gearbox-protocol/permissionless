// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {IImmutableOwnable} from "./IImmutableIOwnable.sol";

interface IBytecodeRepository is IVersion, IImmutableOwnable {
    //
    // ERRORS
    //
    error BytecodeIsNotApprovedException(bytes32 contractType, uint256 version);

    // Thrown if the deployed contract has a different contractType/version than it's indexed in the repository
    error IncorrectBytecodeException(bytes32 bytecodeHash);

    // Thrown if the bytecode provided is empty
    error EmptyBytecodeException();

    // Thrown if someone tries to deploy the contract with the same address
    error BytecodeAlreadyExistsAtAddressException(address);

    // Thrown if domain + postfix length is more than 30 symbols (doesn't fit into bytes32)
    error TooLongContractTypeException(string);

    //  Thrown if requested bytecode wasn't found in the repository
    error BytecodeIsNotUploadedException(bytes32 bytecodeHash);

    // Thrown if someone tries to replace existing bytecode with the same contact type & version
    error BytecodeAlreadyExistsException();

    // Thrown if requested bytecode wasn't found in the repository
    error BytecodeIsNotAuditedException();

    // Thrown if someone tries to deploy a contract which wasn't audited enough
    error ContractIsNotAuditedException();

    error SignerIsNotAuditorException(address signer);

    // Thrown when an attempt is made to add an auditor that already exists
    error AuditorAlreadyAddedException();

    // Thrown when an auditor is not found in the repository
    error AuditorNotFoundException();

    // Thrown if the caller is not the deployer of the bytecode
    error NotDeployerException();

    // Thrown if the caller does not have valid auditor permissions
    error NoValidAuditorPermissionsAException();

    /// @notice Thrown when trying to deploy contract with forbidden bytecode
    error BytecodeForbiddenException(bytes32 bytecodeHash);

    /// @notice Thrown when trying to deploy contract with incorrect domain ownership
    error NotDomainOwnerException();

    /// @notice Thrown when trying to deploy contract with incorrect domain ownership
    error NotAllowedSystemContractException(bytes32 bytecodeHash);

    /// @notice Thrown when trying to deploy contract with incorrect contract type
    error ContractNameVersionAlreadyExistsException();

    error OnlyAuthorCanSyncException();

    error AuditorAlreadySignedException();

    error NoValidAuditorSignatureException();

    error InvalidAuthorSignatureException();
    //
    // EVENTS
    //

    // Emitted when new smart contract was deployed
    event DeployContact(address indexed addr, bytes32 indexed contractType, uint256 indexed version);

    // Event emitted when a new auditor is added to the repository
    event AddAuditor(address indexed auditor, string name);

    // Event emitted when an auditor is forbidden from the repository
    event RemoveAuditor(address indexed auditor);

    // Event emitted when new bytecode is uploaded to the repository
    event UploadBytecode(
        bytes32 indexed metaHash, string contractType, uint256 indexed version, address indexed author, string source
    );

    // Event emitted when bytecode is signed by an auditor
    event BytecodeSigned(bytes32 indexed metaHash, address indexed signer, string reportUrl, bytes signature);

    // Event emitted when a public domain is added
    event AddPublicDomain(bytes32 indexed domain);

    // Event emitted when a public domain is removed
    event RemovePublicDomain(bytes32 indexed domain);

    // Event emitted when contract type owner is removed
    event RemoveContractTypeOwner(bytes32 indexed contractType);

    // Event emitted when bytecode is forbidden
    event ForbidBytecode(bytes32 indexed bytecodeHash);

    // Event emitted when token specific postfix is set
    event SetTokenSpecificPostfix(address indexed token, bytes32 indexed postfix);

    // Event emitted when bytecode is approved
    event ApproveContract(bytes32 indexed bytecodeHash, bytes32 indexed contractType, uint256 version);

    // Event emitted when bytecode is revoked
    event RevokeApproval(bytes32 indexed bytecodeHash, bytes32 indexed contractType, uint256 version);

    // FUNCTIONS

    function deploy(bytes32 type_, uint256 version_, bytes memory constructorParams, bytes32 salt)
        external
        returns (address);

    function computeAddress(
        bytes32 type_,
        uint256 version_,
        bytes memory constructorParams,
        bytes32 salt,
        address deployer
    ) external view returns (address);

    function getTokenSpecificPostfix(address token) external view returns (bytes32);

    function getLatestVersion(bytes32 type_) external view returns (uint256);

    function getLatestMinorVersion(bytes32 type_, uint256 majorVersion) external view returns (uint256);

    function getLatestPatchVersion(bytes32 type_, uint256 minorVersion) external view returns (uint256);
}
