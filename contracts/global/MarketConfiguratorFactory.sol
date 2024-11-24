// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";

import {
    AP_BYTECODE_REPOSITORY,
    AP_GEAR_STAKING,
    AP_MARKET_CONFIGURATOR,
    AP_MARKET_CONFIGURATOR_FACTORY,
    AP_MARKET_CONFIGURATOR_LEGACY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";

import {MarketConfiguratorLegacy} from "../market/legacy/MarketConfiguratorLegacy.sol";
import {MarketConfigurator} from "../market/MarketConfigurator.sol";
import {TreasurySplitter} from "../market/TreasurySplitter.sol";

contract MarketConfiguratorFactory is Ownable2Step, IMarketConfiguratorFactory {
    using Address for address;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR_FACTORY;

    /// @notice Address of the address provider
    address public immutable override addressProvider;

    /// @notice Address of the bytecode repository
    address public immutable override bytecodeRepository;

    /// @dev Set of market configurators
    EnumerableSet.AddressSet internal _marketConfiguratorsSet;

    /// @dev Set of shutdown market configurators
    EnumerableSet.AddressSet internal _shutdownMarketConfiguratorsSet;

    modifier onlyMarketConfigurators() {
        if (!_marketConfiguratorsSet.contains(msg.sender)) revert CallerIsNotMarketConfiguratorException();
        _;
    }

    modifier onlyMarketConfiguratorOwner(address marketConfigurator) {
        // QUESTION: should shutdown configurators be able to perform some actions?
        if (!_marketConfiguratorsSet.contains(marketConfigurator)) revert AddressIsNotMarketConfiguratorException();
        if (MarketConfigurator(marketConfigurator).owner() != msg.sender) {
            revert CallerIsNotMarketConfiguratorOwnerException();
        }
        _;
    }

    constructor(address addressProvider_, address owner_) {
        addressProvider = addressProvider_;
        bytecodeRepository = _getContract(AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL);
        // QUESTION: read owner_ from AP? use AP's owner?
        _transferOwnership(owner_);
    }

    function isMarketConfigurator(address address_) external view override returns (bool) {
        return _marketConfiguratorsSet.contains(address_);
    }

    function getMarketConfigurators() external view override returns (address[] memory) {
        return _marketConfiguratorsSet.values();
    }

    function getShutdownMarketConfigurators() external view override returns (address[] memory) {
        return _shutdownMarketConfiguratorsSet.values();
    }

    function createMarketConfigurator(string calldata name) external override returns (address marketConfigurator) {
        // TODO: transfer ownership to the 2/2 multisig of `msg.sender` and DAO (to be introduced)
        TreasurySplitter treasury = new TreasurySplitter();

        marketConfigurator = _deploy({
            contractType_: AP_MARKET_CONFIGURATOR,
            version_: version,
            constructorParams: abi.encode(name, address(this), msg.sender, treasury),
            salt: bytes32(bytes20(msg.sender))
        });

        _marketConfiguratorsSet.add(marketConfigurator);
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
        _marketConfiguratorsSet.remove(marketConfigurator);
        _shutdownMarketConfiguratorsSet.add(marketConfigurator);
        emit ShutdownMarketConfigurator(marketConfigurator);
    }

    function setVotingContractStatus(address votingContract, VotingContractStatus status)
        external
        override
        onlyMarketConfigurators
    {
        address gearStaking = _getContract(AP_GEAR_STAKING, NO_VERSION_CONTROL);

        // TODO: cleanup
        if (IVotingContract(votingContract).voter() != gearStaking) revert();
        if (IGearStakingV3(gearStaking).version() < 3_10) {
            address marketConfiguratorLegacy = _getContract(AP_MARKET_CONFIGURATOR_LEGACY, NO_VERSION_CONTROL);
            MarketConfiguratorLegacy(marketConfiguratorLegacy).setVotingContractStatus(votingContract, status);
        } else {
            IGearStakingV3(gearStaking).setVotingContractStatus(votingContract, status);
        }
    }

    function configureGearStaking(bytes calldata data) external override onlyOwner {
        address gearStaking = _getContract(AP_GEAR_STAKING, NO_VERSION_CONTROL);

        if (IGearStakingV3(gearStaking).version() < 3_10) {
            address marketConfiguratorLegacy = _getContract(AP_MARKET_CONFIGURATOR_LEGACY, NO_VERSION_CONTROL);
            MarketConfiguratorLegacy(marketConfiguratorLegacy).configureGearStaking(data);
        } else {
            gearStaking.functionCall(data);
        }
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _getContract(bytes32 key, uint256 version_) internal view returns (address) {
        return IAddressProvider(addressProvider).getAddressOrRevert(key, version_);
    }

    function _deploy(bytes32 contractType_, uint256 version_, bytes memory constructorParams, bytes32 salt)
        internal
        returns (address)
    {
        return IBytecodeRepository(bytecodeRepository).deploy(contractType_, version_, constructorParams, salt);
    }
}
