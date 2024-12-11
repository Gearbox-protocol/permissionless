// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {AbstractDeployer} from "../helpers/AbstractDeployer.sol";

import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";

import {
    AP_GEAR_STAKING,
    AP_MARKET_CONFIGURATOR,
    AP_MARKET_CONFIGURATOR_FACTORY,
    AP_MARKET_CONFIGURATOR_LEGACY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";

import {MarketConfiguratorLegacy} from "../market/legacy/MarketConfiguratorLegacy.sol";
import {MarketConfigurator} from "../market/MarketConfigurator.sol";
import {TreasurySplitter} from "../market/TreasurySplitter.sol";

contract MarketConfiguratorFactory is Ownable2Step, AbstractDeployer, IMarketConfiguratorFactory {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR_FACTORY;

    /// @dev Set of registered market configurators
    EnumerableSet.AddressSet internal _registeredMarketConfiguratorsSet;

    /// @dev Set of shutdown market configurators
    EnumerableSet.AddressSet internal _shutdownMarketConfiguratorsSet;

    /// @dev Reverts if caller is not one of market configurators
    modifier onlyMarketConfigurators() {
        if (!_registeredMarketConfiguratorsSet.contains(msg.sender)) revert CallerIsNotMarketConfiguratorException();
        _;
    }

    modifier onlyMarketConfiguratorOwner(address marketConfigurator) {
        // QUESTION: should shutdown configurators be able to perform some actions?
        if (!_registeredMarketConfiguratorsSet.contains(marketConfigurator)) {
            revert AddressIsNotMarketConfiguratorException();
        }
        if (MarketConfigurator(marketConfigurator).owner() != msg.sender) {
            revert CallerIsNotMarketConfiguratorOwnerException();
        }
        _;
    }

    constructor(address addressProvider_, address owner_) AbstractDeployer(addressProvider_) {
        // QUESTION: read owner_ from AP? use AP's owner? who's the owner?
        _transferOwnership(owner_);
    }

    function isMarketConfigurator(address account) external view override returns (bool) {
        return _registeredMarketConfiguratorsSet.contains(account);
    }

    function getMarketConfigurators() external view override returns (address[] memory) {
        return _registeredMarketConfiguratorsSet.values();
    }

    function getMarketConfigurator(uint256 index) external view returns (address) {
        return _registeredMarketConfiguratorsSet.at(index);
    }

    function getNumMarketConfigurators() external view returns (uint256) {
        return _registeredMarketConfiguratorsSet.length();
    }

    function getShutdownMarketConfigurators() external view override returns (address[] memory) {
        return _shutdownMarketConfiguratorsSet.values();
    }

    function createMarketConfigurator(string calldata name) external override returns (address marketConfigurator) {
        // TODO: transfer ownership to the 2/2 multisig of `msg.sender` and DAO (to be introduced)
        TreasurySplitter treasury = new TreasurySplitter();

        // TODO: deploy timelocks
        marketConfigurator = _deploy({
            contractType: AP_MARKET_CONFIGURATOR,
            version: version,
            constructorParams: abi.encode(name, address(this), msg.sender, msg.sender, treasury),
            salt: bytes32(bytes20(msg.sender))
        });

        _registeredMarketConfiguratorsSet.add(marketConfigurator);
        emit CreateMarketConfigurator(marketConfigurator, name);
    }

    function shutdownMarketConfigurator(address marketConfigurator)
        external
        override
        onlyMarketConfiguratorOwner(marketConfigurator)
    {
        address contractsRegister = MarketConfigurator(marketConfigurator).contractsRegister();
        if (IContractsRegister(contractsRegister).getPools().length != 0) {
            revert CantShutdownMarketConfiguratorException();
        }
        _registeredMarketConfiguratorsSet.remove(marketConfigurator);
        _shutdownMarketConfiguratorsSet.add(marketConfigurator);
        emit ShutdownMarketConfigurator(marketConfigurator);
    }

    function setVotingContractStatus(address votingContract, VotingContractStatus status)
        external
        override
        onlyMarketConfigurators
    {
        // QUESTION: do we need to check that votingContract's voter is indeed the GEAR staking contract?
        _configureGearStaking(abi.encodeCall(IGearStakingV3.setVotingContractStatus, (votingContract, status)));
    }

    function configureGearStaking(bytes calldata data) external override onlyOwner {
        _configureGearStaking(data);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _configureGearStaking(bytes memory data) internal {
        address gearStaking = _getContract(AP_GEAR_STAKING, NO_VERSION_CONTROL);
        if (IGearStakingV3(gearStaking).version() < 3_10) {
            address marketConfiguratorLegacy = _getContract(AP_MARKET_CONFIGURATOR_LEGACY, NO_VERSION_CONTROL);
            MarketConfiguratorLegacy(marketConfiguratorLegacy).configureGearStaking(data);
        } else {
            gearStaking.functionCall(data);
        }
    }
}
