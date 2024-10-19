// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

import {
    AP_BYTECODE_REPOSITORY,
    AP_MARKET_CONFIGURATOR_FACTORY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";
import {Call} from "../interfaces/Types.sol";

import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";

abstract contract AbstractFactory is IVersion {
    address public immutable bytecodeRepository;

    address public immutable marketConfiguratorFactory;

    address public immutable addressProvider;

    error CallerIsNotMarketConfiguratorException();

    modifier marketConfiguratorOnly() {
        if (IMarketConfiguratorFactory(marketConfiguratorFactory).isMarketConfigurator(msg.sender)) {
            revert CallerIsNotMarketConfiguratorException();
        }
        _;
    }

    constructor(address _addressProvider) {
        marketConfiguratorFactory =
            IAddressProvider(_addressProvider).getAddressOrRevert(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);

        bytecodeRepository =
            IAddressProvider(_addressProvider).getAddressOrRevert(AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL);

        addressProvider = _addressProvider;
    }
}
