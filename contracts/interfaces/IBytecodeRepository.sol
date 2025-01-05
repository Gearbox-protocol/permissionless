// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

interface IBytecodeRepository is IVersion {
    //
    // ERRORS
    //

    // Thrown if the deployed contract has a different contractType/version than it's indexed in the repository
    error IncorrectBytecodeException();

    // Thrown if the bytecode provided is empty
    error EmptyBytecodeException();

    // Thrown if someone tries to deploy the contract with the same address
    error BytecodeAlreadyExistsAtAddressException(address);

    // Thrown if domain + postfix length is more than 30 symbols (doesn't fit into bytes32)
    error TooLongContractTypeException(string);

    //  Thrown if requested bytecode wasn't found in the repository
    error BytecodeNotFoundException(bytes32 contractType, uint256 version);

    // Thrown if someone tries to replace existing bytecode with the same contact type & version
    error BytecodeAllreadyExistsException(bytes32 contractType, uint256 version);

    // Thrown if someone tries to deploy a contract which wasn't audited enough
    error ContractIsNotAuditedException();

    // Thrown when an attempt is made to add an auditor that already exists
    error AuditorAlreadyAddedException();

    // Thrown when an auditor is not found in the repository
    error AuditorNotFoundException();

    // Thrown if the caller is not the deployer of the bytecode
    error NotDeployerException();

    // Thrown if the caller does not have valid auditor permissions
    error NoValidAuditorPermissionsAException();

    function deploy(bytes32 type_, uint256 version_, bytes memory constructorParams, bytes32 salt)
        external
        returns (address);

    function computeAddress(bytes32 type_, uint256 version_, bytes memory constructorParams, bytes32 salt)
        external
        view
        returns (address);

    function getTokenSpecificPostfix(address token) external view returns (bytes32);

    function getLatestVersion(bytes32 type_) external view returns (uint256);

    function getLatestMinorVersion(bytes32 type_, uint256 majorVersion) external view returns (uint256);

    function getLatestPatchVersion(bytes32 type_, uint256 minorVersion) external view returns (uint256);
}
