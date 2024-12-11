// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {AbstractDeployer} from "../helpers/AbstractDeployer.sol";

import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";
import {Call} from "../interfaces/Types.sol";

import {AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL} from "../libraries/ContractLiterals.sol";

abstract contract AbstractFactory is AbstractDeployer, IFactory {
    // --------------- //
    // STATE VARIABLES //
    // --------------- //

    address public immutable override marketConfiguratorFactory;

    // --------- //
    // MODIFIERS //
    // --------- //

    modifier onlyMarketConfigurators() {
        _ensureCallerIsMarketConfigurator();
        _;
    }

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    constructor(address addressProvider_) AbstractDeployer(addressProvider_) {
        marketConfiguratorFactory = _getContract(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function configure(address, bytes calldata callData) external virtual override returns (Call[] memory) {
        revert ForbiddenConfigurationCallException(bytes4(callData));
    }

    function emergencyConfigure(address, bytes calldata callData) external virtual override returns (Call[] memory) {
        revert ForbiddenEmergencyConfigurationCallException(bytes4(callData));
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _ensureCallerIsMarketConfigurator() internal view {
        if (IMarketConfiguratorFactory(marketConfiguratorFactory).isMarketConfigurator(msg.sender)) {
            revert CallerIsNotMarketConfiguratorException(msg.sender);
        }
    }

    function _isVotingContract(address votingContract) internal view returns (bool) {
        try IVotingContract(votingContract).voter() returns (address) {
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

    function _addToAccessList(address marketConfigurator, address target) internal view returns (Call memory) {
        return Call({
            target: marketConfigurator,
            callData: abi.encodeCall(IMarketConfigurator.addToAccessList, (target, address(this)))
        });
    }
}
