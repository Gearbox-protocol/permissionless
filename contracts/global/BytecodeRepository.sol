// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
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

import {Bytecode, AuditorSignature} from "../interfaces/Types.sol";
import {EIP712Mainnet} from "../helpers/EIP712Mainnet.sol";
import {Domain} from "../libraries/Domain.sol";
import {ImmutableOwnableTrait} from "../traits/ImmutableOwnableTrait.sol";
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

contract BytecodeRepository is ImmutableOwnableTrait, SanityCheckTrait, IBytecodeRepository, EIP712Mainnet {
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

    bytes32 public constant BYTECODE_META_TYPEHASH =
        keccak256("BytecodeMeta(bytes32 contractType,uint256 version,bytes initCode,address author,string source)");

    bytes32 public constant _SIGNATURE_TYPEHASH = keccak256("SignBytecodeHash(bytes32 bytecodeHash,string reportUrl)");

    //
    // STORAGE
    //

    // bytecodeHash =>  Bytecode
    mapping(bytes32 => Bytecode) public bytecodeByHash;

    // bytecodeHash => array of AuditorSignature
    mapping(bytes32 => AuditorSignature[]) internal _auditorSignaturesByHash;

    // contractType => version => bytecodeHash
    mapping(bytes32 => mapping(uint256 => bytes32)) public approvedBytecodeHash;

    // address => bytecodeHash
    mapping(address => bytes32) public deployedContracts;

    // Forbidden initCodes
    mapping(bytes32 => bool) public forbiddenInitCode;

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

    constructor() EIP712Mainnet(contractType.fromSmallString(), version.toString()) ImmutableOwnableTrait(msg.sender) {}

    /// @notice Computes a unique hash for _bytecode metadata
    /// @param _bytecode Bytecode metadata including contract type, version, _bytecode, author and source
    /// @return bytes32 Hash of the metadata
    function computeBytecodeHash(Bytecode calldata _bytecode) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                BYTECODE_META_TYPEHASH,
                _bytecode.contractType,
                _bytecode.version,
                keccak256(_bytecode.initCode),
                _bytecode.author,
                _bytecode.source
            )
        );
    }

    /// @notice Uploads new _bytecode to the repository
    /// @param _bytecode Bytecode metadata to upload
    /// @dev Only the author can upload on mainnet
    function uploadBytecode(Bytecode calldata _bytecode) external nonZeroAddress(_bytecode.author) {
        if (block.chainid == 1 && msg.sender != _bytecode.author) {
            revert OnlyAuthorCanSyncException();
        }
        // Check if _bytecode is already uploaded
        bytes32 bytecodeHash = computeBytecodeHash(_bytecode);

        if (isBytecodeUploaded(bytecodeHash)) {
            revert BytecodeAlreadyExistsException();
        }

        // Verify author's signature of the _bytecode metadata
        address recoveredAuthor = ECDSA.recover(_hashTypedDataV4(bytecodeHash), _bytecode.authorSignature);
        if (recoveredAuthor != _bytecode.author) {
            revert InvalidAuthorSignatureException();
        }

        // Revert if the initCode is forbidden
        revertIfInitCodeForbidden(_bytecode.initCode);

        // Check if the contract name and version already exists
        if (approvedBytecodeHash[_bytecode.contractType][_bytecode.version] != 0) {
            revert ContractNameVersionAlreadyExistsException();
        }

        bytecodeByHash[bytecodeHash] = _bytecode;

        emit UploadBytecode(
            bytecodeHash,
            _bytecode.contractType.fromSmallString(),
            _bytecode.version,
            _bytecode.author,
            _bytecode.source
        );
    }

    /// @notice Deploys a contract using stored _bytecode
    /// @param _contractType Type identifier of the contract
    /// @param _version Version of the contract to deploy
    /// @param constructorParams Constructor parameters for deployment
    /// @param salt Unique salt for CREATE2 deployment
    /// @return newContract Address of the deployed contract
    function deploy(bytes32 _contractType, uint256 _version, bytes memory constructorParams, bytes32 salt)
        external
        returns (address newContract)
    {
        // Retrieve bytecodeHash
        bytes32 bytecodeHash = approvedBytecodeHash[_contractType][_version];
        if (bytecodeHash == 0) {
            revert BytecodeIsNotApprovedException(_contractType, _version);
        }

        if (!isBytecodeAudited(bytecodeHash)) {
            revert BytecodeIsNotAuditedException();
        }

        Bytecode storage _bytecode = bytecodeByHash[bytecodeHash];

        bytes memory initCode = _bytecode.initCode;

        // Revert if the initCode is forbidden
        revertIfInitCodeForbidden(initCode);

        // Combine code + constructor params
        bytes memory bytecodeWithParams = abi.encodePacked(initCode, constructorParams);

        bytes32 saltUnique = keccak256(abi.encode(salt, msg.sender));

        // Compute CREATE2 address
        newContract = Create2.computeAddress(saltUnique, keccak256(bytecodeWithParams));

        // Check if the contract already deployed
        if (newContract.code.length != 0) {
            revert BytecodeAlreadyExistsAtAddressException(newContract);
        }

        // Deploy
        Create2.deploy(0, saltUnique, bytecodeWithParams);

        // Verify IVersion
        if (IVersion(newContract).contractType() != _contractType || IVersion(newContract).version() != _version) {
            revert IncorrectBytecodeException(bytecodeHash);
        }

        // add to deployedContracts
        deployedContracts[newContract] = bytecodeHash;

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
    function computeAddress(
        bytes32 _contractType,
        uint256 _version,
        bytes memory constructorParams,
        bytes32 salt,
        address deployer
    ) external view returns (address) {
        // Retrieve bytecodeHash
        bytes32 bytecodeHash = approvedBytecodeHash[_contractType][_version];
        if (bytecodeHash == 0) {
            revert BytecodeIsNotApprovedException(_contractType, _version);
        }
        Bytecode storage _bytecode = bytecodeByHash[bytecodeHash];

        // Combine code + constructor params
        bytes memory bytecodeWithParams = abi.encodePacked(_bytecode.initCode, constructorParams);

        bytes32 saltUnique = keccak256(abi.encode(salt, deployer));

        // Return CREATE2 address
        return Create2.computeAddress(saltUnique, keccak256(bytecodeWithParams));
    }

    // Auditing
    // TODO:Author should sign _bytecode _bytecode hash!
    /// @notice Allows auditors to sign _bytecode metadata
    /// @param bytecodeHash Hash of the _bytecode metadata to sign
    /// @param reportUrl URL of the audit report
    /// @param signature Cryptographic signature of the auditor
    function signBytecodeHash(bytes32 bytecodeHash, string calldata reportUrl, bytes memory signature) external {
        // Must point to existing metadata
        if (!isBytecodeUploaded(bytecodeHash)) {
            // TODO: change error message
            revert BytecodeIsNotUploadedException(bytecodeHash);
        }

        // Re-create typed data
        bytes32 structHash = keccak256(abi.encode(_SIGNATURE_TYPEHASH, bytecodeHash, keccak256(bytes(reportUrl))));
        // Hash with our pinned domain
        address signer = ECDSA.recover(_hashTypedDataV4(structHash), signature);

        // Must match msg.sender and be an approved auditor
        if (!_auditors.contains(signer)) {
            revert SignerIsNotAuditorException(signer);
        }

        // do not allow duplicates
        uint256 len = _auditorSignaturesByHash[bytecodeHash].length;
        for (uint256 i = 0; i < len; ++i) {
            if (keccak256(_auditorSignaturesByHash[bytecodeHash][i].signature) == keccak256(signature)) {
                revert AuditorAlreadySignedException();
            }
        }
        _auditorSignaturesByHash[bytecodeHash].push(
            AuditorSignature({reportUrl: reportUrl, auditor: signer, signature: signature})
        );

        emit BytecodeSigned(bytecodeHash, signer, reportUrl, signature);

        _approveContract(bytecodeHash);
    }

    /// @notice Allows owner to mark contracts as system contracts
    /// @param bytecodeHash Hash of the _bytecode metadata to allow
    function allowSystemContract(bytes32 bytecodeHash) external onlyOwner {
        allowedSystemContracts[bytecodeHash] = true;
        _approveContract(bytecodeHash);
    }

    /// @notice Internal function to approve contract _bytecode
    /// @param bytecodeHash Hash of the _bytecode metadata to approve
    function _approveContract(bytes32 bytecodeHash) internal {
        if (!isBytecodeUploaded(bytecodeHash)) {
            return;
        }

        Bytecode storage _bytecode = bytecodeByHash[bytecodeHash];

        bytes32 _contractType = _bytecode.contractType;

        if (approvedBytecodeHash[_contractType][_bytecode.version] != 0) {
            return;
        }

        address author = _bytecode.author;
        if (allowedSystemContracts[bytecodeHash]) {
            // System contracts could have any author if it signed by DAO
            contractTypeOwner[_contractType] = author;
        } else if (isContractNameInPublicDomain(_contractType)) {
            // public domain => (domain, postfix) ownership
            address currentOwner = contractTypeOwner[_contractType];

            if (currentOwner == address(0)) {
                contractTypeOwner[_contractType] = author;
            } else if (currentOwner != author) {
                revert NotDomainOwnerException();
            }
        } else {
            revert NotAllowedSystemContractException(bytecodeHash);
        }

        uint256 bytecodeVersion = _bytecode.version;

        if (approvedBytecodeHash[_bytecode.contractType][bytecodeVersion] == 0) {
            approvedBytecodeHash[_bytecode.contractType][bytecodeVersion] = bytecodeHash;

            uint256 majorVersion = (bytecodeVersion / 100) * 100;
            uint256 minorVersion = ((bytecodeVersion / 10) % 10) * 10 + majorVersion;

            if (latestVersion[_bytecode.contractType] < bytecodeVersion) {
                latestVersion[_bytecode.contractType] = bytecodeVersion;
            }
            if (latestMinorVersion[_bytecode.contractType][majorVersion] < bytecodeVersion) {
                latestMinorVersion[_bytecode.contractType][majorVersion] = bytecodeVersion;
            }
            if (latestPatchVersion[_bytecode.contractType][minorVersion] < bytecodeVersion) {
                latestPatchVersion[_bytecode.contractType][minorVersion] = bytecodeVersion;
            }
        }

        emit ApproveContract(bytecodeHash, _contractType, _bytecode.version);
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

    /// @notice Marks initCode as forbidden
    /// @param initCodeHash Hash of initCode to forbid
    function forbidInitCode(bytes32 initCodeHash) external onlyOwner {
        forbiddenInitCode[initCodeHash] = true;
        emit ForbidBytecode(initCodeHash);
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

    function revokeApproval(bytes32 _contractType, uint256 _version, bytes32 _bytecodeHash) external onlyOwner {
        if (approvedBytecodeHash[_contractType][_version] == _bytecodeHash) {
            approvedBytecodeHash[_contractType][_version] = bytes32(0);
            emit RevokeApproval(_bytecodeHash, _contractType, _version);
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

    function auditorSignaturesByHash(bytes32 bytecodeHash) external view returns (AuditorSignature[] memory) {
        return _auditorSignaturesByHash[bytecodeHash];
    }

    function auditorSignaturesByHash(bytes32 bytecodeHash, uint256 index)
        external
        view
        returns (AuditorSignature memory)
    {
        return _auditorSignaturesByHash[bytecodeHash][index];
    }

    //
    // HELPERS
    //
    function isBytecodeUploaded(bytes32 bytecodeHash) public view returns (bool) {
        return bytecodeByHash[bytecodeHash].author != address(0);
    }

    function revertIfInitCodeForbidden(bytes memory initCode) public view {
        bytes32 initCodeHash = keccak256(initCode);
        if (forbiddenInitCode[initCodeHash]) {
            revert BytecodeForbiddenException(initCodeHash);
        }
    }

    function isBytecodeAudited(bytes32 bytecodeHash) public view returns (bool) {
        uint256 len = _auditorSignaturesByHash[bytecodeHash].length;

        for (uint256 i = 0; i < len; ++i) {
            AuditorSignature memory sig = _auditorSignaturesByHash[bytecodeHash][i];
            if (isAuditor(sig.auditor)) {
                return true;
            }
        }

        return false;
    }
}
