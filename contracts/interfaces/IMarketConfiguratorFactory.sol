// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

// NOTE: owns new AF, BL and GS, can call legacy market configurator to access old AF, BL and GS

interface IMarketConfiguratorFactory {
    function isMarketConfigurator(address) external view returns (bool);

    function marketConfigurators() external view returns (address[] memory);
    function createMarketConfigurator() external returns (address);
    function removeMarketConfigurator(address configurator) external;

    function addCreditManagerToAccountFactory(address creditManager) external;
    function addCreditManagerToBotList(address creditManager) external;
    function setVotingContractStatus(address votingContract, VotingContractStatus status) external;
}
