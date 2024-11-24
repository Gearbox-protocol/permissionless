// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";
import {Call} from "../interfaces/Types.sol";

import {
    AP_BYTECODE_REPOSITORY,
    AP_MARKET_CONFIGURATOR_FACTORY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";

abstract contract AbstractFactory {
    address public immutable addressProvider;
    address public immutable bytecodeRepository;
    address public immutable marketConfiguratorFactory;

    error CallerIsNotMarketConfiguratorException();

    error InvalidConstructorParamsException();

    modifier onlyMarketConfigurators() {
        _ensureCallerIsMarketConfigurator();
        _;
    }

    constructor(address addressProvider_) {
        addressProvider = addressProvider_;
        bytecodeRepository = _getContract(AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL);
        marketConfiguratorFactory = _getContract(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);
    }

    function _ensureCallerIsMarketConfigurator() internal view {
        if (IMarketConfiguratorFactory(marketConfiguratorFactory).isMarketConfigurator(msg.sender)) {
            revert CallerIsNotMarketConfiguratorException();
        }
    }

    function _getContract(bytes32 key, uint256 version) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(key, version);
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

    function _isVotingContract(address contract_) internal view returns (bool) {
        try IVotingContract(contract_).voter() returns (address) {
            return true;
        } catch {
            return false;
        }
    }

    function _setVotingContractStatus(address votingContract, bool allowed) internal view returns (Call memory) {
        return Call({
            target: marketConfiguratorFactory,
            callData: abi.encodeCall(
                IMarketConfiguratorFactory.setVotingContractStatus,
                (votingContract, allowed ? VotingContractStatus.ALLOWED : VotingContractStatus.UNVOTE_ONLY)
            )
        });
    }
}
