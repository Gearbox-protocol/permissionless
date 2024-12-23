// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

interface IMarketConfiguratorFactory is IVersion {
    event CreateMarketConfigurator(address indexed marketConfigurator, string name);
    event ShutdownMarketConfigurator(address indexed marketConfigurator);

    error AddressIsNotMarketConfiguratorException();
    error CallerIsNotMarketConfiguratorException();
    error CallerIsNotMarketConfiguratorOwnerException();
    error CantShutdownMarketConfiguratorException();

    function isMarketConfigurator(address account) external view returns (bool);
    function getMarketConfigurators() external view returns (address[] memory);
    function getShutdownMarketConfigurators() external view returns (address[] memory);
    function createMarketConfigurator(string calldata name) external returns (address marketConfigurator);
    function shutdownMarketConfigurator(address marketConfigurator) external;

    function configureGearStaking(bytes calldata data) external;
    function setVotingContractStatus(address votingContract, VotingContractStatus status) external;
}
