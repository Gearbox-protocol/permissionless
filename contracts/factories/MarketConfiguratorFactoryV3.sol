// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketConfigurator} from "./MarketConfigurator.sol";
import {ACL} from "../primitives/ACL.sol";
import {ContractsRegister} from "../primitives/ContractsRegister.sol";
import {IAddressProviderV3} from "../interfaces/IAddressProviderV3.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/IVersion.sol";

import {IBytecodeRepository} from "./IBytecodeRepository.sol";
import {AP_MARKET_CONFIGURATOR} from "./ContractLiterals.sol";

interface IAdapterDeployer {
    function deploy(address creditManager, address target, bytes calldata specificParams) external returns (address);
}

contract MarketConfiguratorFactoryV3 is AbstractFactory, IVersion {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    uint256 latestMCversion;

    /// @notice Contract version
    error CantRemoveMarketConfiguratorWithExistingPoolsException();

    mapping(address => uint8) public targetTypes;
    mapping(uint8 => mapping(uint256 => address)) public adapterDeployers;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {}

    function addMarketConfigurator(
        address riskCurator,
        address _treasury,
        string calldata name,
        address _vetoAdmin,
        bytes32 _salt
    ) external apOwnerOnly {
        ACL acl = new ACL();
        ContractsRegister contractsRegister = new ContractsRegister(address(acl));
        bytes memory constructorParams =
            abi.encode(addressProvider, acl, contractsRegister, _treasury, name, _vetoAdmin);

        address _marketConfigurator = IBytecodeRepository(bytecodeRepository).deploy(
            AP_MARKET_CONFIGURATOR, latestMCversion, constructorParams, _salt
        );

        /// Makes market configurator contract owner
        acl.transferOwnership(_marketConfigurator);

        IAddressProviderV3(addressProvider).addMarketConfigurator(_marketConfigurator);
    }

    function removeMarketConfigurator(address _marketConfigurator) external apOwnerOnly {
        if (MarketConfigurator(_marketConfigurator).pools().length != 0) {
            revert CantRemoveMarketConfiguratorWithExistingPoolsException();
        }
        IAddressProviderV3(addressProvider).removeMarketConfigurator(_marketConfigurator);
    }
}
