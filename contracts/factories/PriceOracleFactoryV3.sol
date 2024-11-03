// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

import {IPriceFeed, IUpdatablePriceFeed} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IPriceFeed.sol";
import {IPriceFeedStore} from "../interfaces/IPriceFeedStore.sol";
import {NestedPriceFeeds} from "../libraries/NestedPriceFeeds.sol";

import {
    AddressIsNotContractException,
    IncorrectTokenContractException,
    PriceFeedDoesNotExistException
} from "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {PriceFeedValidationTrait} from "@gearbox-protocol/core-v3/contracts/traits/PriceFeedValidationTrait.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {AbstractFactory} from "./AbstractFactory.sol";

import {
    AP_PRICE_ORACLE,
    AP_PRICE_ORACLE_FACTORY,
    AP_PRICE_FEED_STORE,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";
import {Call, DeployResult} from "../interfaces/Types.sol";
import {IPriceOracleV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";

contract PriceOracleFactoryV3 is AbstractFactory, PriceFeedValidationTrait {
    using NestedPriceFeeds for IPriceFeed;

    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_PRICE_ORACLE_FACTORY;

    // Thrown if an unauthorized price feed is used for a token
    error PriceFeedNotAllowedException(address token, address priceFeed);

    address public immutable priceFeedStore;

    /// @notice Constructor
    /// @param addressProvider Address provider contract address
    constructor(address addressProvider) AbstractFactory(addressProvider) {
        priceFeedStore = IAddressProvider(addressProvider).getAddressOrRevert(AP_PRICE_FEED_STORE, NO_VERSION_CONTROL);
    }

    function deployPriceOracle(bytes calldata constructorParams)
        external
        marketConfiguratorOnly
        returns (DeployResult memory)
    {
        // Get required addresses from MarketConfigurator
        address acl = IMarketConfigurator(msg.sender).acl();

        address priceOracle = IBytecodeRepository(bytecodeRepository).deploy(
            AP_PRICE_ORACLE, version, constructorParams, bytes32(bytes20(msg.sender))
        );

        address[] memory accessList = new address[](1);
        accessList[0] = priceOracle;

        return DeployResult({newContract: priceOracle, accessList: accessList, onInstallOps: new Call[](0)});
    }

    //
    // MARKET HOOKS
    //
    function onUpdatePriceOracle(address pool, address priceOracle, address prevOracle)
        external
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {
        address[] memory tokens = IPriceOracleV3(prevOracle).getTokens();

        uint256 numTokens = tokens.length;
        for (uint256 i; i < numTokens; ++i) {
            _setPriceFeed(priceOracle, tokens[i], _getPriceFeed(prevOracle, tokens[i], false), false);

            address reserve = _getPriceFeed(prevOracle, tokens[i], true);
            if (reserve != address(0)) _setPriceFeed(priceOracle, tokens[i], reserve, true);
        }
    }

    function onSetPriceFeed(address pool, address token, address priceFeed)
        external
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {
        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address priceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);

        // TODO: compute call length somehow?
        // IDEA: limit number of recursive oracles up to 10?
        _setPriceFeed(priceOracle, token, priceFeed, false);
    }

    function onSetReservePriceFeed(address pool, address token, address priceFeed)
        external
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {
        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address priceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);
        _setPriceFeed(priceOracle, token, priceFeed, true);
    }

    //
    // INTERNAL

    // @price
    function _setPriceFeed(address priceOracle, address token, address priceFeed, bool reserve)
        internal
        returns (Call[] memory calls)
    {
        if (!IPriceFeedStore(priceFeedStore).isAllowedPriceFeed(token, priceFeed)) {
            revert PriceFeedNotAllowedException(token, priceFeed);
        }

        // TODO: rewrite to dynamic calculation
        calls = new Call[](1);

        // TODO: fix calldata generation
        uint32 stalenessPeriod = IPriceFeedStore(priceFeedStore).getStalenessPeriod(priceFeed);
        calls[0] = (reserve)
            ? _setReservePriceFeed(priceOracle, token, priceFeed, stalenessPeriod)
            : _setPriceFeed(priceOracle, token, priceFeed, stalenessPeriod);

        // TODO: add dynamic filling calls array
        _addUpdatableFeeds(priceOracle, priceFeed);
    }

    //
    // INTERNALS

    function _setPriceFeed(address priceOracle, address token, address priceFeed, uint32 stalenessPeriod)
        internal
        view
        returns (Call memory call)
    {
        call = Call({
            target: priceOracle,
            callData: abi.encodeCall(IPriceOracleV3.setPriceFeed, (token, priceFeed, stalenessPeriod))
        });
    }

    function _setReservePriceFeed(address priceOracle, address token, address priceFeed, uint32 stalenessPeriod)
        internal
        view
        returns (Call memory call)
    {
        call = Call({
            target: priceOracle,
            callData: abi.encodeCall(IPriceOracleV3.setReservePriceFeed, (token, priceFeed, stalenessPeriod))
        });
    }

    function _addUpdatableFeeds(address priceOracle, address priceFeed) internal returns (Call[] memory calls) {
        try IUpdatablePriceFeed(priceFeed).updatable() returns (bool updatable) {
            if (updatable) IPriceOracleV3(priceOracle).addUpdatablePriceFeed(priceFeed);
        } catch {}
        address[] memory underlyingFeeds = IPriceFeed(priceFeed).getUnderlyingFeeds();
        uint256 numFeeds = underlyingFeeds.length;
        for (uint256 i; i < numFeeds; ++i) {
            _addUpdatableFeeds(priceOracle, underlyingFeeds[i]);
        }
    }

    function _getPriceFeed(address priceOracle, address token, bool reserve) internal view returns (address) {
        return reserve
            ? IPriceOracleV3(priceOracle).reservePriceFeeds(token)
            : IPriceOracleV3(priceOracle).priceFeeds(token);
    }
}
