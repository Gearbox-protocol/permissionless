// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IRateKeeperFactory} from "../interfaces/IRateKeeperFactory.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IMarketHooks} from "../interfaces/IMarketHooks.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketHookFactory} from "./MarketHookFactory.sol";
import {
    DOMAIN_RATE_KEEPER,
    AP_RATE_KEEPER_FACTORY,
    NO_VERSION_CONTROL,
    AP_GEAR_STAKING
} from "../libraries/ContractLiterals.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";

import {IRateKeeper} from "../interfaces/extensions/IRateKeeper.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";

import {Call, DeployResult} from "../interfaces/Types.sol";
import {CallBuilder} from "../libraries/CallBuilder.sol";

contract RateKeeperFactoryV3 is AbstractFactory, MarketHookFactory, IRateKeeperFactory {
    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_RATE_KEEPER_FACTORY;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {}

    //
    /**
     * @notice Deploys a new rate keeper for a given pool
     * @param pool The address of the pool for which to deploy the rate keeper
     * @param postfix The postfix identifying the type of rate keeper to deploy
     * @param encodedParams Additional encoded parameters specific to the rate keeper type
     * @return rateKeeper The address of the newly deployed rate keeper
     */
    function deployRateKeeper(address pool, bytes32 postfix, bytes calldata encodedParams)
        external
        override
        marketConfiguratorOnly
        returns (DeployResult memory)
    {
        bytes memory constructorParams;

        if (postfix == "GAUGE") {
            address ap = IMarketConfigurator(msg.sender).addressProvider();
            address _gearStaking = IAddressProvider(ap).getAddressOrRevert(AP_GEAR_STAKING, NO_VERSION_CONTROL);
            constructorParams = abi.encode(pool, _gearStaking);
        } else if (postfix == "TUMBLER") {
            address quotaKeeper = IPoolV3(pool).poolQuotaKeeper();
            uint256 epochLength_ = abi.decode(encodedParams, (uint256));
            constructorParams = abi.encode(quotaKeeper, epochLength_);
        } else {
            // Default case for all further rate keepers
            address quotaKeeper = IPoolV3(pool).poolQuotaKeeper();
            constructorParams = abi.encode(quotaKeeper, msg.sender, encodedParams);
        }

        // QUESTION: should rateKeeper know about pool?
        address rateKeeper = IBytecodeRepository(bytecodeRepository).deployByDomain(
            DOMAIN_RATE_KEEPER, postfix, version, constructorParams, bytes32(bytes20(msg.sender))
        );

        address[] memory accessList = new address[](1);
        accessList[0] = rateKeeper;

        return DeployResult({newContract: rateKeeper, accessList: accessList, onInstallOps: new Call[](0)});
    }

    // @dev Hook which is called when rate keeper is configured
    // @param rateKeeper - rate keeper address
    // @param callData - call data to be executed
    // @return calls - array of calls to be executed
    function configure(address rateKeeper, bytes calldata callData) external view returns (Call[] memory calls) {
        // TODO: implement
    }

    //
    // POOL HOOKS
    //

    // @dev Hook which is called when new token is added to the market
    // @param pool - pool address
    // @param token - token address
    // @param priceFeed - price feed address
    // @return calls - array of calls to be executed
    function onAddToken(address pool, address token, address priceFeed)
        external
        view
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        address rateKeeper = _rateKeeperByPool(pool);
        calls = CallBuilder.build(_addToken(rateKeeper, token, _getRateKeeperType(rateKeeper)));
    }

    // @dev This hook exists for RateKeeperFactoryV3 only, and it's called when
    // rate keeper is removed from the market (replaced with a new one)
    // @param rateKeeper - rate keeper address
    // @return calls - array of calls to be execute
    function onRemoveRateKeeper(address pool, address rateKeeper)
        external
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(_gaugeSetFrozenEpoch(rateKeeper));
        } else {
            // TODO: add generic function for all rate keepers
        }
    }

    //
    // INTERNAL
    //
    function _rateKeeperByPool(address pool) internal view returns (address) {
        address quotaKeeper = IPoolV3(pool).poolQuotaKeeper();
        // `gauge` method is legacy method originally designed in V3_0
        return IPoolQuotaKeeperV3(quotaKeeper).gauge();
    }

    function _getRateKeeperType(address rateKeeper) internal view returns (bytes32) {
        try IRateKeeper(rateKeeper).contractType() returns (bytes32 type_) {
            return type_;
        } catch {
            return "RK_GAUGE";
        }
    }

    function _gaugeSetFrozenEpoch(address rateKeeper) internal pure returns (Call memory call) {
        call = Call({target: rateKeeper, callData: abi.encodeCall(IGaugeV3.setFrozenEpoch, true)});
    }

    // GENERATION
    function _addToken(address rateKeeper, address token, bytes32 type_) internal pure returns (Call memory call) {
        bytes memory callData;
        if (type_ == "RK_GAUGE") {
            // {token: token, minRate: 1, maxRate: 1}
            callData = abi.encodeCall(IGaugeV3.addQuotaToken, (token, 1, 1));
        } else if (type_ == "RK_TUMBLER") {
            // ({token: token, rate: 1})
            callData = abi.encodeCall(ITumblerV3.addToken, (token, 1));
        } else {
            callData = abi.encodeCall(IRateKeeper.addToken, token);
        }
        call = Call({target: rateKeeper, callData: callData});
    }
}
