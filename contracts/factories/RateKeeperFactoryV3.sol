// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {AccountFactoryV3} from "@gearbox-protocol/core-v3/contracts/core/AccountFactoryV3.sol";
import {BotListV3} from "@gearbox-protocol/core-v3/contracts/core/BotListV3.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IRateKeeperFactory} from "../interfaces/IRateKeeperFactory.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {DOMAIN_RATE_KEEPER} from "../libraries/ContractLiterals.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";

import {Call} from "../interfaces/Types.sol";

// Domain which represents contractType in Bytecode Repository
bytes32 constant BYTECODE_REPOSITORY_DOMAIN = "RK_";

// RKF

contract RateKeeperFactoryV3 is AbstractFactory, IRateKeeperFactory {
    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_RATE_FACTORY;

    constructor(address _marketConfigurator) AbstractFactory(_marketConfigurator) {}

    //
    /**
     * @notice Deploys a new rate keeper for a given pool
     * @param pool The address of the pool for which to deploy the rate keeper
     * @param rateKeeperPostfix The postfix identifying the type of rate keeper to deploy
     * @param encodedParams Additional encoded parameters specific to the rate keeper type
     * @return rateKeeper The address of the newly deployed rate keeper
     * @return onInstallOps An array of Call structs representing operations to perform after installation
     */
    function deployRateKeeper(address pool, bytes32 rateKeeperPostfix, bytes calldata encodedParams)
        external
        override
        marketConfiguratorOnly
        returns (address rateKeeper, Call[] memory onInstallOps)
    {
        bytes memory constructorParams;

        if (rateKeeperPostfix == "GAUGE") {
            address ap = IMarketConfigurator(msg.sender).addressProvider();
            address _gearStaking = IAddressProvider(ap).getAddressOrRevert(AP_GEAR_STAKING, NO_VERSION_CONTROL);
            constructorParams = abi.encode(pool, _gearStaking);
        } else if (rateKeeperPostfix == "TUMBLER") {
            address quotaKeeper = IPoolV3(pool).poolQuotaKeeper();
            uint256 epochLength_ = abi.decode(encodedParams, (uint256));
            constructorParams = abi.encode(quotaKeeper, epochLength_);
        } else {
            // Default case for all further rate keepers
            address quotaKeeper = IPoolV3(pool).poolQuotaKeeper();
            constructorParams = abi.encode(quotaKeeper, msg.sender, encodedParams);
        }

        rateKeeper = IBytecodeRepository(bytecodeRepository).deployByDomain(
            DOMAIN_RATE_KEEPER, postfix, version, constructorParams, bytes32(marketConfigurator)
        );
    }

    //
    // MODULAR HOOKS
    //

    // @dev Hook which is called when new token is added to the market
    // @param pool - pool address
    // @param token - token address
    // @param priceFeed - price feed address
    // @return calls - array of calls to be executed
    function onAddToken(address pool, address token, address priceFeed) external view returns (Call[] memory calls) {
        address rateKeeper = _rateKeeperByPool(pool);
        calls = Call.build(_addToken(rateKeeper, token, _getRateKeeperType(rateKeeper)));
    }

    // @dev This hook exists for RateKeeperFactoryV3 only, and it's called when
    // rate keeper is removed from the market (replaced with a new one)
    // @param rateKeeper - rate keeper address
    // @return calls - array of calls to be execute
    function onRemoveRateKeeper(address rateKeeper) external override returns (Call[] memory calls) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") {
            calls = Call.build(_gaugeSetFrozenEpoch(rateKeeper));
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
        try IRateKeeperExt(rateKeeper).contractType() returns (bytes32 type_) {
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
            callData = abi.encodeCall(IRateKeeperExt.addToken, token);
        }
        call = Call({target: rateKeeper, callData: callData});
    }
}
