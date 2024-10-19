// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketConfigurator} from "../market/MarketConfigurator.sol";
import {ACL} from "../market/ACL.sol";
import {ContractsRegister} from "../market/ContractsRegister.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";

import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {AP_MARKET_CONFIGURATOR, AP_MARKET_CONFIGURATOR_FACTORY} from "../libraries/ContractLiterals.sol";

interface IAdapterDeployer {
    function deploy(address creditManager, address target, bytes calldata specificParams) external returns (address);
}

contract MarketConfiguratorFactoryV3 is AbstractFactory {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR_FACTORY;

    uint256 public latestMCversion;

    /// @notice Contract version
    error CantRemoveMarketConfiguratorWithExistingPoolsException();

    mapping(address => uint8) public targetTypes;
    mapping(uint8 => mapping(uint256 => address)) public adapterDeployers;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {}

    function createMarketConfigurator(address _treasury, string calldata name, address _vetoAdmin) external {
        ACL acl = new ACL();
        ContractsRegister contractsRegister = new ContractsRegister(address(acl));

        // TODO: add selecting / deploying of treasury splitter
        bytes memory constructorParams =
            abi.encode(msg.sender, addressProvider, acl, contractsRegister, _treasury, name, _vetoAdmin);

        address _marketConfigurator = IBytecodeRepository(bytecodeRepository).deploy(
            AP_MARKET_CONFIGURATOR, latestMCversion, constructorParams, bytes32(bytes20(msg.sender))
        );

        /// Makes market configurator contract owner
        acl.transferOwnership(_marketConfigurator);

        IAddressProvider(addressProvider).addMarketConfigurator(_marketConfigurator);
    }

    // function removeMarketConfigurator(address _marketConfigurator) external apOwnerOnly {
    //     if (MarketConfigurator(_marketConfigurator).pools().length != 0) {
    //         revert CantRemoveMarketConfiguratorWithExistingPoolsException();
    //     }
    //     IAddressProvider(addressProvider).removeMarketConfigurator(_marketConfigurator);
    // }
}
