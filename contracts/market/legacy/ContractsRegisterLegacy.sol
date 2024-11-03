// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

// import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
// import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

// import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
// import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";

// import {IContractsRegister} from "../../interfaces/extensions/IContractsRegister.sol";
// import {MarketConfiguratorLegacy} from "./MarketConfiguratorLegacy.sol";

// contract ContractsRegisterLegacy is ACLTrait, IContractsRegister {
//     using EnumerableSet for EnumerableSet.AddressSet;

//     /// @notice Contract version
//     uint256 public constant override version = 3_10;

//     /// @notice Contract type
//     bytes32 public constant override contractType = "CONTRACTS_REGISTER_LEGACY";

//     address public immutable legacyContractsRegister;

//     EnumerableSet.AddressSet internal _removedPoolsSet;
//     EnumerableSet.AddressSet internal _removedCreditManagersSet;

//     constructor(address acl_, address legacyContractsRegister_) ACLTrait(acl_) {
//         legacyContractsRegister = legacyContractsRegister_;
//     }

//     function getPools() external view override returns (address[] memory pools) {
//         address[] memory allPools = IContractsRegister(legacyContractsRegister).getPools();
//         uint256 numPools = allPools.length;
//         pools = new address[](numPools);
//         uint256 numMatchingPools;
//         for (uint256 i; i < numPools; ++i) {
//             if (_removedPoolsSet.contains(allPools[i]) || !_matchVersion(allPools[i])) continue;
//             pools[numMatchingPools++] = allPools[i];
//         }
//         assembly {
//             mstore(pools, numMatchingPools)
//         }
//     }

//     function isPool(address pool) external view override returns (bool) {
//         return IContractsRegister(legacyContractsRegister).isPool(pool) && !_removedPoolsSet.contains(pool)
//             && _matchVersion(pool);
//     }

//     function getCreditManagers() external view override returns (address[] memory creditManagers) {
//         address[] memory allManagers = IContractsRegister(legacyContractsRegister).getCreditManagers();
//         uint256 numManagers = allManagers.length;
//         creditManagers = new address[](numManagers);
//         uint256 numMatchingManagers;
//         for (uint256 i; i < numManagers; ++i) {
//             if (_removedCreditManagersSet.contains(allManagers[i]) || !_matchVersion(allManagers[i])) continue;
//             creditManagers[numMatchingManagers++] = allManagers[i];
//         }
//         assembly {
//             mstore(creditManagers, numMatchingManagers)
//         }
//     }

//     function isCreditManager(address creditManager) external view override returns (bool) {
//         return IContractsRegister(legacyContractsRegister).isCreditManager(creditManager)
//             && !_removedCreditManagersSet.contains(creditManager) && _matchVersion(creditManager);
//     }

//     function addPool(address pool) external override configuratorOnly {
//         MarketConfiguratorLegacy(_marketConfigurator()).addPool(pool);
//         _removedPoolsSet.remove(pool);
//     }

//     function removePool(address pool) external override configuratorOnly {
//         if (_removedPoolsSet.add(pool)) emit RemovePool(pool);
//     }

//     function addCreditManager(address creditManager) external override configuratorOnly {
//         MarketConfiguratorLegacy(_marketConfigurator()).addCreditManager(creditManager);
//         _removedCreditManagersSet.remove(creditManager);
//     }

//     function removeCreditManager(address creditManager) external override configuratorOnly {
//         if (_removedCreditManagersSet.add(creditManager)) emit RemoveCreditManager(creditManager);
//     }

//     function _marketConfigurator() internal view returns (address) {
//         return Ownable(acl).owner();
//     }

//     function _matchVersion(address contract_) internal view returns (bool) {
//         try IVersion(contract_).version() returns (uint256 version_) {
//             return version_ >= 3_00 && version_ < 4_00;
//         } catch {
//             return false;
//         }
//     }

//     //
//     function getCreditManagersByPool(address pool) external view returns (address[] memory) {}

//     function getPriceOracle(address pool) external view returns (address) {}

//     // Factories
//     function getPoolFactory(address pool) external view returns (address) {}
//     function getCreditFactory(address creditManager) external view returns (address) {}
//     function getPriceOracleFactory(address pool) external view returns (address) {}

//     function setPoolFactory(address pool, address factory) external {}
//     function setCreditFactory(address creditManager, address factory) external {}
//     function setPriceOracleFactory(address pool, address factory) external {}

//     function getRateKeeperFactory(address pool) external view returns (address) {}
//     function getInterestRateModelFactory(address pool) external view returns (address) {}
//     function setRateKeeperFactory(address pool, address factory) external {}
//     function setInterestRateModelFactory(address pool, address factory) external {}
// }
