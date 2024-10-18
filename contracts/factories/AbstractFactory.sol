// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {
    AP_BYTECODE_REPOSITORY,
    AP_MARKET_CONFIGURATOR_FACTORY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";
import {Call} from "../interfaces/Types.sol";
import {IModularFactory} from "../interfaces/IModularFactory.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";

abstract contract AbstractFactory is IModularFactory {
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

    //
    // HOOKS
    //
    function onAddToken(address pool, address token, address priceFeed) external view returns (Call[] memory calls) {}

    function onUpdateInterestModel(address pool, address newModel)
        external
        virtual
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {}

    function onAddCreditManager(address newCreditManager)
        external
        virtual
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {}

    function onUpdatePriceOracle(address newPriceOracle)
        external
        virtual
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {}

    // MIGRATION
    function onMigrate(address _contract, address prevFactory)
        external
        virtual
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {}

    function onUninstall(address _contract) external virtual marketConfiguratorOnly returns (Call[] memory calls) {}
}
