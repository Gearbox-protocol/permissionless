// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {AP_BYTECODE_REPOSITORY} from "../libraries/ContractLiterals.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {SanityCheckTrait} from "@gearbox-protocol/core-v3/contracts/traits/SanityCheckTrait.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {LibString} from "@solady/utils/LibString.sol";
import "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {BytecodeWithMeta, AuditorSignature} from "../interfaces/Types.sol";

/**
 * @title BytecodeRepository
 *
 * @notice
 * The `BytecodeRepository` is a singleton contract responsible for deploying all contracts in the system for risk curators.
 *
 * Each contract is identified by two parameters:
 * - ContractType: bytes32. Can be further split into two parts:
 *   - Domain: Represents the fundamental category or name of the smart contract. For example,
 *     contracts like `Pools` or `CreditManagers` use the contract name as the domain.
 *   - Postfix: For contracts that offer different implementations under the same interface
 *     (such as interest rate models, adapters, or price feeds), the domain remains fixed.
 *     Variations are distinguished using a postfix. This is established by convention.
 * - Version: uint256: Specifies the version of the contract in semver. (example: 3_10)
 *
 * ContractType Convention:
 *  - The contract type follows a capitalized snake_case naming convention
 *    without any version information (example: "POOL", "CREDIT_MANAGER")
 *  - List of domains:
 *    RK_ - rate keepers. Supports IRateKeeperBase interface.
 *    IRM_ - interest rate models
 *
 * This structure ensures consistency and clarity when deploying and managing contracts within the system.
 */
contract BytecodeRepository is Ownable, SanityCheckTrait, IBytecodeRepository, EIP712 {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ECDSA for bytes32;
    using LibString for bytes32;
    using LibString for string;

    //
    // CONSTANTS
    //

    /// @notice Meta info about contract type & version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_BYTECODE_REPOSITORY;

    // Hardcode chainId=1 by overriding _domainSeparatorV4 and _buildDomainSeparator.
    // We'll store hashed name and version from the constructor.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;

    // EIP-712 domain typeHash
    bytes32 private constant _EIP712_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // Name and version hashed
    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;

    // Hardcoded chainId = 1
    uint256 private constant _HARDCODED_CHAIN_ID = 1;

    bytes32 private constant _SIGNATURE_TYPEHASH = keccak256("SignBytecodeMetaHash(bytes32 metaHash,string reportUrl)");

    //
    // ERRORS
    //

    /// @notice Thrown when trying to deploy contract with forbidden bytecode
    error BytecodeForbiddenException(bytes32 bytecodeHash);

    /// @notice Thrown when trying to deploy contract that already exists at the computed address
    error BytecodeAlreadyExistsAtAddressException(address addr);

    /// @notice Thrown when trying to deploy contract with incorrect bytecode
    error IncorrectBytecodeException();

    /// @notice Thrown when trying to sign contract that is not audited
    error ContractIsNotAuditedException();

    /// @notice Thrown when trying to deploy contract with incorrect domain ownership
    error NotDomainOwnerException();

    /// @notice Thrown when trying to deploy contract with incorrect contract type
    error ContractNameVersionAlreadyExistsException();

    error OnlyAuthorCanSyncException();

    //
    // EVENTS
    //

    // Emitted when new smart contract was deployed
    event DeployContact(address indexed addr, bytes32 indexed contractType, uint256 indexed version);

    // Event emitted when a new auditor is added to the repository
    event AddAuditor(address indexed auditor, string name);

    // Event emitted when an auditor is forbidden from the repository
    event RemoveAuditor(address indexed auditor, string name);

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

    // Event emitted when bytecode is forbidden
    event ForbidBytecode(bytes32 indexed bytecodeHash);

    // Event emitted when token specific postfix is set
    event SetTokenSpecificPostfix(address indexed token, bytes32 indexed postfix);

    //
    // VARIABLES
    //

    // metaHash =>  BytecodeWithMeta
    mapping(bytes32 => BytecodeWithMeta) public bytecodeWithMetaByHash;

    // metaHash => array of AuditorSignature
    mapping(bytes32 => AuditorSignature[]) public auditorSignaturesByHash;

    // contractName => version => metaHash
    mapping(bytes32 => mapping(uint256 => bytes32)) public approvedBytecodeMetaHash;

    // Forbidden bytecodes (by keccak256 of the raw bytecode)
    mapping(bytes32 => bool) public forbiddenBytecode;

    // Allowed system contracts
    mapping(bytes32 => bool) public allowedSystemContracts;

    // Distinguish system vs. public domains
    EnumerableSet.Bytes32Set private _publicDomains;

    // if contractType is public
    mapping(bytes32 => address) public contractTypeOwner;

    // Auditors
    EnumerableSet.AddressSet private _auditors;

    // token => tokenSpecificPostfix
    mapping(address => bytes32) public tokenSpecificPostfixes;

    // +++ Governance +++
    // forbiddenBytecode
    // removeDomainOwner
    // removeByteCode contractType + version

    EnumerableSet.UintSet internal _hashStorage;

    // Auditors

    // Keep all auditors joined the repository
    EnumerableSet.AddressSet internal _auditors;

    // Store auditors info
    mapping(address => string) public auditorName;

    // Postfixes are used to deploy unique contract versions inherited from
    // the base contract but differ when used with specific tokens.
    // For example, the USDT pool, which supports fee computation without errors
    mapping(address => bytes32) public tokenSpecificPostfixes;

    constructor() EIP712(contractType, version) {
        _HASHED_NAME = keccak256(contractType);
        _HASHED_VERSION = keccak256(version);

        _CACHED_DOMAIN_SEPARATOR =
            _buildDomainSeparator(_EIP712_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION, _HARDCODED_CHAIN_ID, address(this));
    }

    function computeContractName(bytes32 _domain, bytes32 _postfix) public pure returns (bytes32) {
        if (_postfix == bytes32(0)) {
            return _domain;
        }

        string memory domainStr = LibString.toSmallString(_domain);
        string memory postfixStr = LibString.toSmallString(_postfix);
        return computeContractName(domainStr, postfixStr);
    }

    function computeContractName(string memory _domain, string memory _postfix) public pure returns (bytes32) {
        if (_postfix.length == 0) {
            return LibString.toSmallBytes32(_domain);
        }

        return LibString.toSmallBytes32(string.concat(_domain, "_", _postfix));
    }

    function computeBytecodeMetaHash(BytecodeWithMeta calldata _meta) public pure returns (bytes32) {
        return keccak256(
            abi.encode(_meta.contractName, _meta.version, keccak256(_meta.bytecode), _meta.author, _meta.source)
        );
    }

    function uploadBytecode(BytecodeWithMeta calldata _meta) external nonZeroAddress(_meta.author) {
        if (block.chainid == 1 && msg.sender != _meta.author) {
            revert OnlyAuthorCanSyncException();
        }
        // Check if bytecode is already uploaded
        bytes32 metaHash = computeBytecodeMetaHash(_meta);

        if (bytecodeWithMetaByHash[metaHash].author != address(0)) {
            revert BytecodeAllreadyExistsException(_meta.contractName, _meta.version);
        }

        // Check if the bytecode is forbidden
        bytes32 bytecodeHash = keccak256(_meta.bytecode);
        if (forbiddenBytecode[bytecodeHash]) {
            revert BytecodeForbiddenException(bytecodeHash);
        }

        // Check if the contract name and version already exists
        if (approvedBytecodeMetaHash[_meta.contractName][_meta.version] != 0) {
            revert ContractNameVersionAlreadyExistsException();
        }

        bytecodeWithMetaByHash[metaHash] = _meta;

        // Emit with string-based domain/postfix
        string memory ctString = LibString.toSmallString(_meta.contractName);

        emit UploadBytecode(metaHash, ctString, _meta.version, _meta.author, _meta.source);
    }

    //
    // DEPLOYMENT
    //
    function deploy(bytes32 _contractType, uint256 _version, bytes memory constructorParams, bytes32 salt)
        external
        returns (address newContract)
    {
        // Retrieve metaHash
        bytes32 metaHash = approvedBytecodeMetaHash[_contractType][_version];
        if (metaHash == 0) {
            revert ContractIsNotAuditedException();
        }
        BytecodeWithMeta storage meta = bytecodeWithMetaByHash[metaHash];

        // Check if forbidden
        bytes32 rawHash = keccak256(meta.bytecode);
        if (forbiddenBytecode[rawHash]) {
            revert BytecodeForbiddenException(rawHash);
        }

        // Combine code + constructor params
        bytes memory bytecodeWithParams = abi.encodePacked(meta.bytecode, constructorParams);

        // CREATE2 address
        bytes32 codeHash = keccak256(bytecodeWithParams);
        newContract = Create2.computeAddress(salt, codeHash, address(this));
        if (newContract.code.length != 0) {
            revert BytecodeAlreadyExistsAtAddressException(newContract);
        }

        // Deploy
        Create2.deploy(0, salt, bytecodeWithParams);

        // Verify IVersion
        if (IVersion(newContract).contractType() != _contractType || IVersion(newContract).version() != _version) {
            revert IncorrectBytecodeException();
        }

        emit DeployContact(newContract, _contractType, _version);

        // Auto-transfer ownership if IOwnable
        try Ownable(newContract).transferOwnership(msg.sender) {} catch {}
    }

    // Auditing
    function signBytecodeMetaHash(bytes32 metaHash, string calldata reportUrl, bytes calldata signature) external {
        // Must point to existing metadata
        if (bytecodeWithMetaByHash[metaHash].author == address(0)) {
            revert ContractIsNotAuditedException();
        }

        // Re-create typed data
        bytes32 structHash = keccak256(abi.encode(_SIGNATURE_TYPEHASH, metaHash, keccak256(bytes(reportUrl))));
        // Hash with our pinned domain
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        // Must match msg.sender and be an approved auditor
        if (!_auditors.contains(signer)) {
            revert ContractIsNotAuditedException();
        }

        auditorSignaturesByHash[metaHash].push(AuditorSignature(reportUrl, signature));

        emit BytecodeSigned(metaHash, signer, reportUrl);

        bytes32 _contractType = bytecodeWithMetaByHash[metaHash].contractType;

        if (isContractNameInPublicDomain(_contractType)) {
            // public domain => (domain, postfix) ownership
            address currentOwner = contractTypeOwner[_contractType];
            address author = bytecodeWithMetaByHash[metaHash].author;

            if (currentOwner == address(0)) {
                contractTypeOwner[_contractType] = author;
            } else if (currentOwner != author) {
                revert NotDomainOwnerException();
            }
            _approveContract(metaHash);
        } else if (allowedSystemContracts[metaHash]) {
            _approveContract(metaHash);
        }
    }

    // Non-revertable function for non-blocking execution
    function allowSystemContract(bytes32 metaHash) external onlyOwner {
        allowedSystemContracts[metaHash] = true;
        _approveContract(metaHash);
    }

    function _approveContract(bytes32 metaHash) internal {
        BytecodeWithMeta storage bytecodeWithMeta = bytecodeWithMetaByHash[metaHash];
        if (bytecodeWithMeta.author != address(0)) {
            approvedBytecodeMetaHash[bytecodeWithMeta.contractType][bytecodeWithMeta.version] = metaHash;
        }
    }

    //
    // Auditor management
    //
    function addAuditor(address auditor) external onlyOwner nonZeroAddress(auditor) {
        bool added = _auditors.add(auditor);
        if (added) {
            emit AddAuditor(auditor);
        }
    }

    function removeAuditor(address auditor) external onlyOwner {
        bool removed = _auditors.remove(auditor);
        if (removed) {
            emit RemoveAuditor(auditor);
        }
    }

    function isAuditor(address auditor) public view returns (bool) {
        return _auditors.contains(auditor);
    }

    function getAuditors() external view returns (address[] memory) {
        return _auditors.values();
    }

    //
    // DOMAIN MANAGEMENT
    //

    // This function is non-revertable not to block InstanceManager
    // Incorrect domain will be ignored
    function addPublicDomain(bytes32 domain) external onlyOwner {
        if (domain == bytes32(0)) {
            return;
        }

        bytes memory domainStr = bytes(LibString.toSmallString(domain));
        if (domainStr.contains("_")) {
            return;
        }

        if (_publicDomains.add(domain)) {
            emit AddPublicDomain(domain);
        }
    }

    function removePublicDomain(bytes32 domain) external onlyOwner {
        if (_publicDomains.remove(domain)) {
            emit RemovePublicDomain(domain);
        }
    }

    function forbidBytecode(bytes32 bytecodeHash) external onlyOwner {
        forbiddenBytecode[bytecodeHash] = true;
        emit ForbidBytecode(bytecodeHash);
    }

    function setTokenSpecificPostfix(address token, bytes32 postfix) external onlyOwner {
        tokenSpecificPostfixes[token] = postfix;
        emit SetTokenSpecificPostfix(token, postfix);
    }

    // GETTERS

    function isContractNameInPublicDomain(bytes32 contractName) public view returns (bool) {
        string memory contractNameStr = LibString.toSmallString(contractName);
        uint256 underscoreIndex = LibString.indexOf(contractNameStr, "_");

        // If no underscore found, treat the whole name as domain
        if (underscoreIndex == LibString.NOT_FOUND) {
            return false;
        }

        // Extract domain part before underscore and convert to bytes32
        string memory domainStr = LibString.slice(contractNameStr, 0, underscoreIndex);
        bytes32 domain = LibString.toSmallBytes32(domainStr);

        return isPublicDomain(domain);
    }

    function isPublicDomain(bytes32 domain) public view returns (bool) {
        return _publicDomains.contains(domain);
    }

    function listPublicDomains() external view returns (bytes32[] memory) {
        return _publicDomains.values();
    }

    // EIP-712 Helpers
    /**
     * @dev Build a domain separator that uses chainId=1.
     */
    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash,
        uint256 chainId,
        address verifyingContract
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, chainId, verifyingContract));
    }

    /**
     * @dev Return our cached domain separator (with chainId=1).
     */
    function _domainSeparatorV4() internal view override returns (bytes32) {
        return _CACHED_DOMAIN_SEPARATOR;
    }

    /**
     * @dev Hash typed data using the pinned domain separator.
     */
    function _hashTypedDataV4(bytes32 structHash) internal view override returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}
