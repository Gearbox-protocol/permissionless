// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

struct CreateMarketParams {
    address underlying;
    // Pool params
    string symbol;
    string name;
    bytes poolParams;
    // PriceOracle params
    address underlyingPriceFeed;
    bytes priceOracleParams;
    // InterestRateModel params
    bytes32 irmPostfix;
    bytes irmParams;
    // RateKeeper
    bytes32 rateKeeperPostfix;
    bytes rateKeeperParams;
}

interface IMarketConfigurator is IVersion {
    // ------ //
    // ERRORS //
    // ------ //

    // Thrown if hook attempting to call a contract which is node in accessList
    error ContractNotAssignedToFactoryException(address);

    // Thrown if factory attempting to overwrite exsting addess in accessList
    error ContractAlreadyInAccessListException(address);

    function addressProvider() external view returns (address);
    function acl() external view returns (address);
    function contractsRegister() external view returns (address);
    function treasury() external view returns (address);

    function emergencyLiquidators() external view returns (address[] memory);
}
