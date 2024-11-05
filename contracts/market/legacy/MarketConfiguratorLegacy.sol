// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {IContractsRegister} from "../../interfaces/extensions/IContractsRegister.sol";
import {IContractsRegisterLegacy} from "../../interfaces/extensions/IContractsRegisterLegacy.sol";
import {IAddressProvider} from "../../interfaces/IAddressProvider.sol";
import {IMarketConfiguratorFactory} from "../../interfaces/IMarketConfiguratorFactory.sol";

import {AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL} from "../../libraries/ContractLiterals.sol";

import {CreateMarketParams, MarketConfigurator} from "../MarketConfigurator.sol";

contract MarketConfiguratorLegacy is MarketConfigurator {
    address public immutable marketConfiguratorFactory;

    address public immutable gearStaking;
    address public immutable contractsRegisterLegacy;

    error CallerIsNotMarketConfiguratorException();

    modifier marketConfiguratorsOnly() {
        if (!IMarketConfiguratorFactory(marketConfiguratorFactory).isMarketConfigurator(msg.sender)) {
            revert CallerIsNotMarketConfiguratorException();
        }
        _;
    }

    // TODO: reduce the number of constructor arguments
    constructor(
        address riskCurator_,
        address addressProvider_,
        address acl_,
        address contractsRegister_,
        address treasury_,
        address gearStaking_,
        address contractsRegisterLegacy_
    ) MarketConfigurator(riskCurator_, addressProvider_, acl_, contractsRegister_, treasury_) {
        marketConfiguratorFactory =
            IAddressProvider(addressProvider).getAddressOrRevert(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);

        gearStaking = gearStaking_;
        contractsRegisterLegacy = contractsRegisterLegacy_;

        address[] memory pools = IContractsRegisterLegacy(contractsRegisterLegacy).getPools();
        uint256 numPools = pools.length;
        for (uint256 i; i < numPools; ++i) {
            address pool = pools[i];
            if (!_matchVersion(pool)) continue;

            address[] memory creditManagers = IPoolV3(pool).creditManagers();
            uint256 numCreditManagers = creditManagers.length;
            if (numCreditManagers == 0) continue;

            // QUESTION: shall we verify the consistency across all credit managers?
            address priceOracle = ICreditManagerV3(creditManagers[0]).priceOracle();
            IContractsRegister(contractsRegister).createMarket(pool, priceOracle);

            address lossLiquidator =
                ICreditFacadeV3(ICreditManagerV3(creditManagers[0]).creditFacade()).lossLiquidator();
            if (lossLiquidator != address(0)) {
                IContractsRegister(contractsRegister).setLossLiquidator(pool, lossLiquidator);
            }

            for (uint256 j; j < numCreditManagers; ++j) {
                IContractsRegister(contractsRegister).createCreditSuite(pool, creditManagers[j]);
            }

            // TODO: set factories
        }
    }

    function createMarket(CreateMarketParams calldata params) public override onlyOwner returns (address) {
        address pool = super.createMarket(params);
        IContractsRegisterLegacy(contractsRegisterLegacy).addPool(pool);
        return pool;
    }

    function createCreditSuite(address pool, bytes calldata encodedParams)
        public
        override
        onlyOwner
        returns (address)
    {
        address creditManager = super.createCreditSuite(pool, encodedParams);
        IContractsRegisterLegacy(contractsRegisterLegacy).addCreditManager(creditManager);
        return creditManager;
    }

    function setVotingContractStatus(address votingContract, VotingContractStatus status)
        external
        marketConfiguratorsOnly
    {
        // TODO: check that `votingContract` belongs to caller (how though? might not even implement `ACLTrait`)
        IGearStakingV3(gearStaking).setVotingContractStatus(votingContract, status);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _matchVersion(address contract_) internal view returns (bool) {
        try IVersion(contract_).version() returns (uint256 version_) {
            return version_ >= 300 && version_ < 400;
        } catch {
            return false;
        }
    }
}
