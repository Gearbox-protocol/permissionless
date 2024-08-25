// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

import {
    AddressIsNotContractException,
    IncorrectTokenContractException,
    PriceFeedDoesNotExistException
} from "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {ACLNonReentrantTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLNonReentrantTrait.sol";
import {PriceFeedValidationTrait} from "@gearbox-protocol/core-v3/contracts/traits/PriceFeedValidationTrait.sol";

import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";

import {AbstractFactory} from "./AbstractFactory.sol";

contract PriceOracleFactoryV3 is AbstractFactory, PriceFeedValidationTrait, IVersion {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    uint256 poLatestVersion;

    /// @dev Mapping from token address to price feed parameters
    mapping(address => EnumerableSet.AddressSet) internal _priceFeeds;

    /// @notice Constructor
    /// @param addressProvider Address provider contract address
    constructor(address addressProvider) AbstractFactory(addressProvider) {}

    function deployPriceOracle(address _acl, uint256 _version, bytes32 _salt) external returns (address) {
        bytes memory constructorParams = abi.encode(_acl);
        return IBytecodeRepository(bytecodeRepository).deploy("PRICE_ORACLE", _version, constructorParams, _salt);
    }

    function isRegisteredOracle(address token, address priceFeed) external view returns (bool) {}

    function stalenessPeriod(address priceFeed) external view returns (uint32) {}

    /// @dev Validates that `token` is a contract that returns `decimals` within allowed range
    function _validateToken(address token) internal view returns (uint8 decimals) {
        if (!Address.isContract(token)) revert AddressIsNotContractException(token); // U:[PO-4]
        try ERC20(token).decimals() returns (uint8 _decimals) {
            if (_decimals == 0 || _decimals > 18) revert IncorrectTokenContractException(); // U:[PO-4]
            decimals = _decimals; // U:[PO-4]
        } catch {
            revert IncorrectTokenContractException(); // U:[PO-4]
        }
    }
}
