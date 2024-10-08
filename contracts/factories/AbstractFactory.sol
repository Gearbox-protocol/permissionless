// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {APOwnerTrait} from "../traits/APOwnerTrait.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL} from "../libraries/ContractLiterals.sol";

abstract contract AbstractFactory is APOwnerTrait {
    address immutable bytecodeRepository;

    error CallerIsNotMarketConfiguratorException();

    modifier marketConfiguratorOnly() {
        if (IAddressProvider(addressProvider).isMarketConfigurator(msg.sender)) {
            revert CallerIsNotMarketConfiguratorException();
        }
        _;
    }

    constructor(address _addressProvider) APOwnerTrait(_addressProvider) {
        bytecodeRepository =
            IAddressProvider(_addressProvider).getAddressOrRevert(AP_BYTECODE_REPOSITORY, NO_VERSION_CONTROL);
    }
}
