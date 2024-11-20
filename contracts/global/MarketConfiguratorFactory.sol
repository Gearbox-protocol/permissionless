// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {AbstractFactory} from "../factories/AbstractFactory.sol";

import {ACL} from "../market/ACL.sol";
import {ContractsRegister} from "../market/ContractsRegister.sol";
import {MarketConfigurator} from "../market/MarketConfigurator.sol";
import {TreasurySplitter} from "../market/TreasurySplitter.sol";

import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";

import {
    AP_MARKET_CONFIGURATOR,
    AP_MARKET_CONFIGURATOR_FACTORY,
    AP_MARKET_CONFIGURATOR_LEGACY
} from "../libraries/ContractLiterals.sol";

// QUESTION: shall it even inherit `AbstractFactory` which is more about generating calls etc.?
// QUESTION: shall it be ownable?
contract MarketConfiguratorFactory is AbstractFactory, IMarketConfiguratorFactory {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR_FACTORY;

    EnumerableSet.AddressSet internal _marketConfigurators;

    modifier onlyMarketConfiguratorOwner(address marketConfigurator) {
        // TODO: shall also check that `marketConfigurator` is, in fact, a market configurator?
        if (Ownable(marketConfigurator).owner() != msg.sender) revert CallerIsNotMarketConfiguratorOwnerException();
        _;
    }

    constructor(address addressProvider_) AbstractFactory(addressProvider_) {}

    function isMarketConfigurator(address address_) external view override returns (bool) {
        return _marketConfigurators.contains(address_);
    }

    function marketConfigurators() external view override returns (address[] memory) {
        return _marketConfigurators.values();
    }

    function createMarketConfigurator(string calldata name) external override returns (address marketConfigurator) {
        ACL acl = new ACL();
        // TODO: transfer ownership to the 2/2 multisig of `msg.sender` and DAO (to be introduced)
        TreasurySplitter treasury = new TreasurySplitter();

        marketConfigurator = _deploy({
            type_: AP_MARKET_CONFIGURATOR,
            version_: version,
            constructorParams: abi.encode(msg.sender, addressProvider, acl, treasury),
            salt: bytes32(bytes20(msg.sender))
        });

        acl.transferOwnership(marketConfigurator);

        _marketConfigurators.add(marketConfigurator);
        emit CreateMarketConfigurator(marketConfigurator, name);
    }

    // TODO: consider, maybe this should be the DAO-only instead
    function removeMarketConfigurator(address marketConfigurator)
        external
        override
        onlyMarketConfiguratorOwner(marketConfigurator)
    {
        if (!_marketConfigurators.remove(marketConfigurator)) return;
        address contractsRegister = IMarketConfigurator(marketConfigurator).contractsRegister();
        if (IContractsRegister(contractsRegister).getPools().length != 0) {
            revert CantRemoveMarketConfiguratorWithExistingPoolsException();
        }
        emit RemoveMarketConfigurator(marketConfigurator);
    }

    function setVotingContractStatus(address votingContract, VotingContractStatus status)
        external
        override
        onlyMarketConfigurators
    {
        // TODO: cleanup and re-consider logic
        address gearStaking = IVotingContract(votingContract).voter();
        if (IGearStakingV3(gearStaking).version() < 3_10) {
            address marketConfiguratorLegacy = _getLatestContract(AP_MARKET_CONFIGURATOR_LEGACY);
            IGearStakingV3(marketConfiguratorLegacy).setVotingContractStatus(votingContract, status);
        } else {
            IGearStakingV3(gearStaking).setVotingContractStatus(votingContract, status);
        }
    }
}
