// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {IVotingContract} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVotingContract.sol";
import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";

// PoolFactoryV3 is responsible for creating pools and their management
contract GearStakingFactoryV3 {
// function _gearStakring_onInstall(address rateKeeper) internal {
//     if (_isVotingContract(rateKeeper)) {
//         _setVotingContractStatus(rateKeeper, VotingContractStatus.ALLOWED);
//     }
// }

// function _gearStaking_onRemove(address rateKeeper) internal {
//     if (_isVotingContract(rateKeeper)) {
//         _setVotingContractStatus(rateKeeper, VotingContractStatus.UNVOTE_ONLY);
//         try IGaugeV3(rateKeeper).setFrozenEpoch(true) {} catch {}
//     }
// }

// // Could it be IRM for example?

// function _isVotingContract(address rateKeeper) internal view returns (bool) {
//     try IVotingContract(rateKeeper).voter() returns (address) {
//         return true;
//     } catch {
//         return false;
//     }
// }
// @global
// function _setVotingContractStatus(address votingContract, VotingContractStatus status) internal {
//     IMarketConfiguratorFactory(configuratorFactory).setVotingContractStatus(votingContract, status);
// }
}
