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

import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";
import {PriceFeedValidationTrait} from "@gearbox-protocol/core-v3/contracts/traits/PriceFeedValidationTrait.sol";

import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {AbstractFactory} from "./AbstractFactory.sol";

import {AP_PRICE_ORACLE_FACTORY} from "../libraries/ContractLiterals.sol";

contract PriceOracleFactoryV3 is AbstractFactory, PriceFeedValidationTrait, IVersion {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_PRICE_ORACLE_FACTORY;

    address public constant priceFeedStore;

    /// @notice Constructor
    /// @param addressProvider Address provider contract address
    constructor(address addressProvider) AbstractFactory(addressProvider) {
        priceFeedStore = IAddressProvider(addressProvider).getAddressOrRevert(AP_PRICE_FEED_STORE, NO_VERSION_);
    }

    function deployPriceOracle(address _acl, uint256 _version, bytes32 _salt) external returns (address) {
        bytes memory constructorParams = abi.encode(_acl);
        return IBytecodeRepository(bytecodeRepository).deploy("PRICE_ORACLE", _version, constructorParams, _salt);
    }

    function onUpdatePriceOracle(address pool, address priceOracle, address prevOracle)
        external
        returns (Call[] memory calls)
    {
        address[] memory tokens = IPriceOracleV3(prevPriceOracle).getTokens();

        uint256 numTokens = tokens.length;
        for (uint256 i; i < numTokens; ++i) {
            _setPriceFeed(priceOracle, tokens[i], _getPriceFeed(prevPriceOracle, tokens[i], false), false);

            address reserve = _getPriceFeed(prevPriceOracle, tokens[i], true);
            if (reserve != address(0)) _setPriceFeed(priceOracle, tokens[i], reserve, true);
        }
    }

    //
    // HOOKS

    function onSetPriceFeed(address pool, address token, address priceFeed) external returns (Call[] memory calls) {
        address priceOracle = IMarketConfigurator(marketConfigurator).priceOracles(pool);

        // TODO: compute call length somehow?
        // IDEA: limit number of recursive oracles up to 10?
        _setPriceFeed(priceOracle, token, priceFeed, false);
        _addUpdatableFeeds(priceOracle, priceFeed);
    }

    //
    // INTERNAL

    // @price
    function _setPriceFeed(address priceOracle, address token, address priceFeed, bool reserve)
        internal
        view
        returns (Call[] memory calls)
    {
        if (!IPriceFeedStore(priceFeedStore).isAllowedPriceFeed(token, priceFeed)) {
            revert PriceFeedNotAllowedException(token, priceFeed);
        }
        uint32 stalenessPeriod = IPriceFeedStore(priceFeedStore).getStalenessPeriod(priceFeed);
        if (reserve) {
            IPriceOracleV3(priceOracle).setReservePriceFeed(token, priceFeed, stalenessPeriod);
        } else {
            IPriceOracleV3(priceOracle).setPriceFeed(token, priceFeed, stalenessPeriod);
        }
        _addUpdatableFeeds(priceOracle, priceFeed);
    }

    function _addUpdatableFeeds(address priceOracle, address priceFeed) internal view returns (Call[] memory calls) {
        try IUpdatablePriceFeed(priceFeed).updatable() returns (bool updatable) {
            if (updatable) IPriceOracleV3(priceOracle).addUpdatablePriceFeed(priceFeed);
        } catch {}
        address[] memory underlyingFeeds = IPriceFeed(priceFeed).getUnderlyingFeeds();
        uint256 numFeeds = underlyingFeeds.length;
        for (uint256 i; i < numFeeds; ++i) {
            _addUpdatableFeeds(priceOracle, underlyingFeeds[i]);
        }
    }
}
