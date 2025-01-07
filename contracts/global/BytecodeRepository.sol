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
import {EIP712Mainnet} from "../helpers/EIP712Mainnet.sol";
import {Domain} from "../libraries/Domain.sol";

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
contract BytecodeRepository is Ownable, SanityCheckTrait, IBytecodeRepository, EIP712Mainnet {
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using ECDSA for bytes32;
    using LibString for bytes32;
    using LibString for string;
    using LibString for uint256;
    using Domain for string;
    //
    // CONSTANTS
    //

    /// @notice Meta info about contract type & version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_BYTECODE_REPOSITORY;

    bytes32 private constant _SIGNATURE_TYPEHASH = keccak256("SignBytecodeMetaHash(bytes32 metaHash,string reportUrl)");

    //
    // STORAGE
    //

    // metaHash =>  BytecodeWithMeta
    mapping(bytes32 => BytecodeWithMeta) public bytecodeWithMetaByHash;

    // metaHash => array of AuditorSignature
    mapping(bytes32 => AuditorSignature[]) internal _auditorSignaturesByHash;

    // contractType => version => metaHash
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

    // Auditor => name
    mapping(address => string) public auditorName;

    // Postfixes are used to deploy unique contract versions inherited from
    // the base contract but differ when used with specific tokens.
    // For example, the USDT pool, which supports fee computation without errors
    mapping(address => bytes32) public tokenSpecificPostfixes;

    // Version control
    mapping(bytes32 => uint256) public latestVersion;
    mapping(bytes32 => mapping(uint256 => uint256)) public latestMinorVersion;
    mapping(bytes32 => mapping(uint256 => uint256)) public latestPatchVersion;

    constructor(address _owner) EIP712Mainnet(contractType.fromSmallString(), version.toString()) Ownable() {
        _transferOwnership(_owner);
    }

    /// @notice Computes a unique hash for bytecode metadata
    /// @param _meta Bytecode metadata including contract type, version, bytecode, author and source
    /// @return bytes32 Hash of the metadata
    function computeBytecodeMetaHash(BytecodeWithMeta calldata _meta) public pure returns (bytes32) {
        return keccak256(
            abi.encode(_meta.contractType, _meta.version, keccak256(_meta.bytecode), _meta.author, _meta.source)
        );
    }

    /// @notice Uploads new bytecode to the repository
    /// @param _meta Bytecode metadata to upload
    /// @dev Only the author can upload on mainnet
    function uploadBytecode(BytecodeWithMeta calldata _meta) external nonZeroAddress(_meta.author) {
        if (block.chainid == 1 && msg.sender != _meta.author) {
            revert OnlyAuthorCanSyncException();
        }
        // Check if bytecode is already uploaded
        bytes32 metaHash = computeBytecodeMetaHash(_meta);

        if (bytecodeWithMetaByHash[metaHash].author != address(0)) {
            revert BytecodeAllreadyExistsException(_meta.contractType, _meta.version);
        }

        // Verify author's signature of the bytecode metadata
        bytes32 digest = _hashTypedDataV4(metaHash);
        address recoveredAuthor = ECDSA.recover(digest, _meta.authorSignature);
        if (recoveredAuthor != _meta.author) {
            revert InvalidAuthorSignatureException();
        }

        // Check if the bytecode is forbidden
        bytes32 bytecodeHash = keccak256(_meta.bytecode);
        if (forbiddenBytecode[bytecodeHash]) {
            revert BytecodeForbiddenException(bytecodeHash);
        }

        // Check if the contract name and version already exists
        if (approvedBytecodeMetaHash[_meta.contractType][_meta.version] != 0) {
            revert ContractNameVersionAlreadyExistsException();
        }

        bytecodeWithMetaByHash[metaHash] = _meta;

        // Emit with string-based domain/postfix
        string memory ctString = LibString.fromSmallString(_meta.contractType);

        emit UploadBytecode(metaHash, ctString, _meta.version, _meta.author, _meta.source);
    }

    /// @notice Deploys a contract using stored bytecode
    /// @param _contractType Type identifier of the contract
    /// @param _version Version of the contract to deploy
    /// @param constructorParams Constructor parameters for deployment
    /// @param salt Unique salt for CREATE2 deployment
    /// @return newContract Address of the deployed contract
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

        // Check that it has at least one auditor signature
        bool hasValidSignature = false;
        uint256 len = _auditorSignaturesByHash[metaHash].length;

        for (uint256 i = 0; i < len; ++i) {
            AuditorSignature memory sig = _auditorSignaturesByHash[metaHash][i];
            if (isAuditor(sig.auditor)) {
                hasValidSignature = true;
                break;
            }
        }

        if (!hasValidSignature) {
            revert NoValidAuditorSignatureException();
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

    /// @notice Computes the address where a contract would be deployed
    /// @param _contractType Type identifier of the contract
    /// @param _version Version of the contract
    /// @param constructorParams Constructor parameters
    /// @param salt Unique salt for CREATE2 deployment
    /// @return Address where the contract would be deployed
    function computeAddress(bytes32 _contractType, uint256 _version, bytes memory constructorParams, bytes32 salt)
        external
        view
        returns (address)
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
            // should be reverted or returned address(0)
            revert BytecodeForbiddenException(rawHash);
        }

        // Combine code + constructor params
        bytes memory bytecodeWithParams = abi.encodePacked(meta.bytecode, constructorParams);

        // Return CREATE2 address
        bytes32 codeHash = keccak256(bytecodeWithParams);
        return Create2.computeAddress(salt, codeHash, address(this));
    }

    // Auditing
    // TODO:Author should sign bytecode meta hash!
    /// @notice Allows auditors to sign bytecode metadata
    /// @param metaHash Hash of the bytecode metadata to sign
    /// @param reportUrl URL of the audit report
    /// @param signature Cryptographic signature of the auditor
    function signBytecodeMetaHash(bytes32 metaHash, string calldata reportUrl, bytes memory signature) external {
        // Must point to existing metadata
        if (bytecodeWithMetaByHash[metaHash].author == address(0)) {
            // TODO: change error message
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

        // do not allow duplicates
        uint256 len = _auditorSignaturesByHash[metaHash].length;
        for (uint256 i = 0; i < len; ++i) {
            if (keccak256(_auditorSignaturesByHash[metaHash][i].signature) == keccak256(signature)) {
                revert AuditorAlreadySignedException();
            }
        }
        _auditorSignaturesByHash[metaHash].push(
            AuditorSignature({reportUrl: reportUrl, auditor: signer, signature: signature})
        );

        emit BytecodeSigned(metaHash, signer, reportUrl, signature);

        bytes32 _contractType = bytecodeWithMetaByHash[metaHash].contractType;

        if (approvedBytecodeMetaHash[_contractType][bytecodeWithMetaByHash[metaHash].version] == 0) {
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
            } else {
                if (allowedSystemContracts[metaHash]) {
                    _approveContract(metaHash);
                }
            }
        }
    }

    /// @notice Allows owner to mark contracts as system contracts
    /// @param metaHash Hash of the bytecode metadata to allow
    function allowSystemContract(bytes32 metaHash) external onlyOwner {
        allowedSystemContracts[metaHash] = true;
        _approveContract(metaHash);
    }

    /// @notice Internal function to approve contract bytecode
    /// @param metaHash Hash of the bytecode metadata to approve
    function _approveContract(bytes32 metaHash) internal {
        BytecodeWithMeta storage bytecodeWithMeta = bytecodeWithMetaByHash[metaHash];

        // check that bytecodeWithMeta.author is not address(0)
        if (bytecodeWithMeta.author == address(0)) {
            return;
        }

        contractTypeOwner[bytecodeWithMeta.contractType] = bytecodeWithMeta.author;

        uint256 bytecodeVersion = bytecodeWithMeta.version;

        if (approvedBytecodeMetaHash[bytecodeWithMeta.contractType][bytecodeVersion] == 0) {
            approvedBytecodeMetaHash[bytecodeWithMeta.contractType][bytecodeVersion] = metaHash;

            uint256 majorVersion = (bytecodeVersion / 100) * 100;
            uint256 minorVersion = ((bytecodeVersion / 10) % 10) * 10 + majorVersion;

            if (latestVersion[bytecodeWithMeta.contractType] < bytecodeVersion) {
                latestVersion[bytecodeWithMeta.contractType] = bytecodeVersion;
            }
            if (latestMinorVersion[bytecodeWithMeta.contractType][majorVersion] < bytecodeVersion) {
                latestMinorVersion[bytecodeWithMeta.contractType][majorVersion] = bytecodeVersion;
            }
            if (latestPatchVersion[bytecodeWithMeta.contractType][minorVersion] < bytecodeVersion) {
                latestPatchVersion[bytecodeWithMeta.contractType][minorVersion] = bytecodeVersion;
            }
        }
    }

    //
    // Auditor management
    //
    /// @notice Adds a new auditor
    /// @param auditor Address of the auditor
    /// @param name Name of the auditor
    function addAuditor(address auditor, string memory name) external onlyOwner nonZeroAddress(auditor) {
        bool added = _auditors.add(auditor);
        if (added) {
            auditorName[auditor] = name;
            emit AddAuditor(auditor, name);
        }
    }

    /// @notice Removes an auditor
    /// @param auditor Address of the auditor to remove
    function removeAuditor(address auditor) external onlyOwner {
        bool removed = _auditors.remove(auditor);
        if (removed) {
            emit RemoveAuditor(auditor);
        }
    }

    /// @notice Checks if an address is an approved auditor
    /// @param auditor Address to check
    /// @return bool True if address is an approved auditor
    function isAuditor(address auditor) public view returns (bool) {
        return _auditors.contains(auditor);
    }

    /// @notice Returns list of all approved auditors
    /// @return Array of auditor addresses
    function getAuditors() external view returns (address[] memory) {
        return _auditors.values();
    }

    //
    // DOMAIN MANAGEMENT
    //

    /// @notice Adds a new public domain
    /// @param domain Domain identifier to add
    /// @dev Non-revertable to avoid blocking InstanceManager
    function addPublicDomain(bytes32 domain) external onlyOwner {
        if (domain == bytes32(0)) {
            return;
        }

        if (LibString.fromSmallString(domain).contains("_")) {
            return;
        }

        if (_publicDomains.add(domain)) {
            emit AddPublicDomain(domain);
        }
    }

    /// @notice Removes a public domain
    /// @param domain Domain identifier to remove
    function removePublicDomain(bytes32 domain) external onlyOwner {
        if (_publicDomains.remove(domain)) {
            emit RemovePublicDomain(domain);
        }
    }

    /// @notice Marks bytecode as forbidden
    /// @param bytecodeHash Hash of bytecode to forbid
    function forbidBytecode(bytes32 bytecodeHash) external onlyOwner {
        forbiddenBytecode[bytecodeHash] = true;
        emit ForbidBytecode(bytecodeHash);
    }

    /// @notice Sets token-specific postfix
    /// @param token Token address
    /// @param postfix Postfix to associate with token
    function setTokenSpecificPostfix(address token, bytes32 postfix) external onlyOwner {
        tokenSpecificPostfixes[token] = postfix;
        emit SetTokenSpecificPostfix(token, postfix);
    }

    /// @notice Removes contract type owner
    /// @param _contractType Contract type to remove owner from
    /// @dev Used to remove malicious auditors and cybersquatters
    function removeContractTypeOwner(bytes32 _contractType) external onlyOwner {
        if (contractTypeOwner[_contractType] != address(0)) {
            contractTypeOwner[_contractType] = address(0);
            emit RemoveContractTypeOwner(_contractType);
        }
    }

    // GETTERS

    /// @notice Checks if a contract name belongs to public domain
    /// @param _contractType Contract type to check
    /// @return bool True if contract is in public domain
    function isContractNameInPublicDomain(bytes32 _contractType) public view returns (bool) {
        string memory contractNameStr = _contractType.fromSmallString();
        return isPublicDomain(contractNameStr.extractDomain().toSmallString());
    }

    /// @notice Checks if a domain is public
    /// @param domain Domain to check
    /// @return bool True if domain is public
    function isPublicDomain(bytes32 domain) public view returns (bool) {
        return _publicDomains.contains(domain);
    }

    /// @notice Returns list of all public domains
    /// @return Array of public domain identifiers
    function listPublicDomains() external view returns (bytes32[] memory) {
        return _publicDomains.values();
    }

    /// @notice Gets token-specific postfix
    /// @param token Token address to query
    /// @return bytes32 Postfix associated with token
    function getTokenSpecificPostfix(address token) external view returns (bytes32) {
        return tokenSpecificPostfixes[token];
    }

    /// @notice Gets latest version for a contract type
    /// @param _contractType Contract type to query
    /// @return uint256 Latest version number (0 if none exists)
    function getLatestVersion(bytes32 _contractType) external view returns (uint256) {
        return latestVersion[_contractType];
    }

    /// @notice Gets latest minor version for a major version
    /// @param _contractType Contract type to query
    /// @param majorVersion Major version number
    /// @return uint256 Latest minor version number
    function getLatestMinorVersion(bytes32 _contractType, uint256 majorVersion) external view returns (uint256) {
        return latestMinorVersion[_contractType][majorVersion];
    }

    /// @notice Gets latest patch version for a minor version
    /// @param _contractType Contract type to query
    /// @param minorVersion Minor version number
    /// @return uint256 Latest patch version number
    function getLatestPatchVersion(bytes32 _contractType, uint256 minorVersion) external view returns (uint256) {
        return latestPatchVersion[_contractType][minorVersion];
    }

    function auditorSignaturesByHash(bytes32 metaHash) external view returns (AuditorSignature[] memory) {
        return _auditorSignaturesByHash[metaHash];
    }

    function auditorSignaturesByHash(bytes32 metaHash, uint256 index) external view returns (AuditorSignature memory) {
        return _auditorSignaturesByHash[metaHash][index];
    }
}
