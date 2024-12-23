// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";

import {AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL} from "../libraries/ContractLiterals.sol";

abstract contract AbstractDeployer {
    /// @notice Address of the address provider
    address public immutable addressProvider;

    /// @notice Address of the bytecode repository
    address public immutable bytecodeRepository;

    constructor(address addressProvider_) {
        addressProvider = addressProvider_;
        bytecodeRepository = _getContract(AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL);
    }

    function _getContract(bytes32 key, uint256 version) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(key, version);
    }

    function _tryGetContract(bytes32 key, uint256 version) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddress(key, version);
    }

    function _deploy(bytes32 contractType, uint256 version, bytes memory constructorParams, bytes32 salt)
        internal
        returns (address)
    {
        return IBytecodeRepository(bytecodeRepository).deploy(contractType, version, constructorParams, salt);
    }

    function _deployByDomain(
        bytes32 domain,
        bytes32 postfix,
        uint256 version,
        bytes memory constructorParams,
        bytes32 salt
    ) internal returns (address) {
        return IBytecodeRepository(bytecodeRepository).deployByDomain(domain, postfix, version, constructorParams, salt);
    }

    function _getTokenSpecificPostfix(address token) internal view returns (bytes32) {
        return IBytecodeRepository(bytecodeRepository).getTokenSpecificPostfix(token);
    }
}
