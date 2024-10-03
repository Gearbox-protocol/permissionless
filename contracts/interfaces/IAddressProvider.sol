// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

struct ContractValue {
    string key;
    address value;
    uint256 version;
}

interface IAddressProviderEvents {
    /// @notice Emitted when an address is set for a contract key
    event SetAddress(string key, address indexed value, uint256 version);

    /// @notice Emitted when a new market configurator added
    event AddMarketConfigurator(address indexed marketConfigurator);

    /// @notice Emitted when existing market configurator was removed
    event RemoveMarketConfigurator(address indexed marketConfigurator);
}

/// @title Address provider interface
interface IAddressProvider is IAddressProviderEvents, IVersion {
    function owner() external view returns (address);

    function addresses(string memory key, uint256 _version) external view returns (address);

    function getAddressOrRevert(string memory key, uint256 _version) external view returns (address);

    function getAddressOrRevert(bytes32 key, uint256 _version) external view returns (address);

    function getAllSavedContracts() external view returns (ContractValue[] memory);

    function getLatestAddressOrRevert(string memory key) external view returns (address);

    function getLatestAddressOrRevert(bytes32 _key) external view returns (address result);

    function setAddress(string memory key, address addr, bool saveVersion) external;

    function setAddress(address addr, bool saveVersion) external;

    function addMarketConfigurator(address _marketConfigurator) external;

    function removeMarketConfigurator(address _marketConfigurator) external;

    function marketConfigurators() external view returns (address[] memory);

    function isMarketConfigurator(address riskCurator) external view returns (bool);

    function registerPool(address pool) external;

    function registerCreditManager(address creditManager) external;

    function setVotingContractStatus(address votingContract, VotingContractStatus status) external;

    function marketConfiguratorByPool(address creditManager) external view returns (address);

    function marketConfiguratorByCreditManager(address creditManager) external view returns (address);
}
