// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {IContractsRegisterExt} from "../../interfaces/extensions/IContractsRegisterExt.sol";
import {MarketConfigurator} from "../MarketConfigurator.sol";

/// @dev While newer implementations of account factory, bot list and GEAR staking are ownable,
///      older ones share the same ACL as deployed markets, so market configurator of the latter
///      automatically becomes the only entrypoint to those three contracts.
contract MarketConfiguratorLegacy is MarketConfigurator {
    address public immutable accountFactory;
    address public immutable botList;
    address public immutable gearStaking;
    address public immutable legacyContractsRegister;

    modifier onlyConfiguratorFactory() {
        require(msg.sender == configuratorFactory);
        _;
    }

    modifier onlyContractsRegister() {
        require(msg.sender == contractsRegister);
        _;
    }

    constructor(
        address riskCurator_,
        address addressProvider_,
        address acl_,
        address contractsRegister_,
        address treasury_,
        bytes memory controllerParams,
        // QUESTION: can we read it from AP?
        address gearStaking_,
        address legacyContractsRegister_
    ) MarketConfigurator(riskCurator_, addressProvider_, acl_, contractsRegister_, treasury_, controllerParams) {
        gearStaking = gearStaking_;
        legacyContractsRegister = legacyContractsRegister_;
    }

    function addPool(address pool) external onlyContractsRegister {
        IContractsRegisterExt(legacyContractsRegister).addPool(pool);
    }

    function addCreditManager(address creditManager) external onlyContractsRegister {
        IContractsRegisterExt(legacyContractsRegister).addCreditManager(creditManager);
    }

    function addCreditManagerToFactory(address creditManager) external onlyConfiguratorFactory {}

    function addCreditManagerToBotList(address creditManager) external onlyConfiguratorFactory {
        // setCreditManagerApprovedStatus(address,bool)
    }

    function setVotingContractStatus(address votingContract, VotingContractStatus status)
        external
        onlyConfiguratorFactory
    {
        IGearStakingV3(gearStaking).setVotingContractStatus(votingContract, status);
    }
}
