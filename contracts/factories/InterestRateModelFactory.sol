// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IInterestRateModelFactory} from "../interfaces/IInterestRateModelFactory.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IMarketHooks} from "../interfaces/IMarketHooks.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {AP_INTEREST_RATE_MODEL_FACTORY, DOMAIN_IRM} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketHooks} from "./MarketHooks.sol";

contract InterestRateModelFactory is AbstractFactory, MarketHooks, IInterestRateModelFactory {
    using CallBuilder for Call[];

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_INTEREST_RATE_MODEL_FACTORY;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {}

    function deployInterestRateModel(address pool, DeployParams calldata params)
        external
        override
        returns (DeployResult memory)
    {
        if (params.postfix != "IRM_LINEAR") {
            (address decodedAddressProvider, address decodedPool) =
                abi.decode(params.constructorParams[:64], (address, address));
            if (decodedAddressProvider != addressProvider || decodedPool != pool) {
                revert InvalidConstructorParamsException();
            }
        }

        address irm = _deployByDomain({
            domain: DOMAIN_IRM,
            postfix: params.postfix,
            version_: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(msg.sender))
        });

        address[] memory accessList = new address[](1);
        accessList[0] = irm;

        return DeployResult({newContract: irm, accessList: accessList, onInstallOps: new Call[](0)});
    }

    // ------------ //
    // MARKET HOOKS //
    // ------------ //

    function onUpdateInterestRateModel(address, address newInterestRateModel, address oldInterestRateModel)
        external
        view
        override(IMarketHooks, MarketHooks)
        returns (Call[] memory calls)
    {
        if (_isVotingContract(oldInterestRateModel)) {
            calls = calls.append(_setVotingContractStatus(oldInterestRateModel, VotingContractStatus.UNVOTE_ONLY));
        }
        if (_isVotingContract(newInterestRateModel)) {
            calls = calls.append(_setVotingContractStatus(newInterestRateModel, VotingContractStatus.ALLOWED));
        }
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function configure(address irm, bytes calldata callData) external pure returns (Call[] memory calls) {
        // TODO: consider explicity forbidding `setController` just in case, though it can be restricted in spec
        return CallBuilder.build(Call({target: irm, callData: callData}));
    }

    function manage(address, bytes calldata callData)
        external
        override
        onlyMarketConfigurators
        returns (Call[] memory)
    {
        // TODO: implement
        revert ForbiddenManagementCall(bytes4(callData));
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _setVotingContractStatus(address interestRateModel, VotingContractStatus status)
        internal
        view
        returns (Call memory)
    {
        return Call({
            target: msg.sender,
            callData: abi.encodeCall(IGearStakingV3.setVotingContractStatus, (interestRateModel, status))
        });
    }
}
