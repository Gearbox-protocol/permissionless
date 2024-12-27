// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IRateKeeper} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IRateKeeper.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";

import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IMarketFactory} from "../interfaces/factories/IMarketFactory.sol";
import {IRateKeeperFactory} from "../interfaces/factories/IRateKeeperFactory.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {
    DOMAIN_RATE_KEEPER,
    AP_RATE_KEEPER_FACTORY,
    NO_VERSION_CONTROL,
    AP_GEAR_STAKING
} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {AbstractMarketFactory} from "./AbstractMarketFactory.sol";

contract RateKeeperFactory is AbstractMarketFactory, IRateKeeperFactory {
    using CallBuilder for Call[];

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_RATE_KEEPER_FACTORY;

    /// @notice Constructor
    /// @param addressProvider_ Address provider contract address
    constructor(address addressProvider_) AbstractFactory(addressProvider_) {}

    // ---------- //
    // DEPLOYMENT //
    // ---------- //

    function deployRateKeeper(address pool, DeployParams calldata params)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        if (params.postfix == "GAUGE") {
            (address decodedPool, address decodedGearStaking) = abi.decode(params.constructorParams, (address, address));
            if (decodedPool != pool || decodedGearStaking != _getAddressOrRevert(AP_GEAR_STAKING, NO_VERSION_CONTROL)) {
                revert InvalidConstructorParamsException();
            }
        } else if (params.postfix == "TUMBLER") {
            (address decodedPool,) = abi.decode(params.constructorParams, (address, uint256));
            if (decodedPool != pool) {
                revert InvalidConstructorParamsException();
            }
        } else {
            _validateDefaultConstructorParams(pool, params.constructorParams);
        }

        address rateKeeper = _deployLatestPatch({
            contractType: _getContractType(DOMAIN_RATE_KEEPER, params.postfix),
            minorVersion: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(msg.sender))
        });

        return DeployResult({
            newContract: rateKeeper,
            onInstallOps: CallBuilder.build(_authorizeFactory(msg.sender, pool, rateKeeper))
        });
    }

    // ------------ //
    // MARKET HOOKS //
    // ------------ //

    function onCreateMarket(address, address, address, address rateKeeper, address, address)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        return _installRateKeeper(rateKeeper, _getRateKeeperType(rateKeeper));
    }

    function onShutdownMarket(address pool)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        address rateKeeper = _rateKeeper(_quotaKeeper(pool));
        return _uninstallRateKeeper(rateKeeper, _getRateKeeperType(rateKeeper));
    }

    function onUpdateRateKeeper(address pool, address newRateKeeper, address oldRateKeeper)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory calls)
    {
        address[] memory tokens = _quotedTokens(_quotaKeeper(pool));
        uint256 numTokens = tokens.length;
        calls = new Call[](numTokens);
        bytes32 type_ = _getRateKeeperType(newRateKeeper);
        for (uint256 i; i < numTokens; ++i) {
            calls[i] = _addToken(newRateKeeper, tokens[i], type_);
        }
        calls = calls.extend(
            _uninstallRateKeeper(oldRateKeeper, _getRateKeeperType(oldRateKeeper)).extend(
                _installRateKeeper(newRateKeeper, type_)
            ).append(_unauthorizeFactory(msg.sender, pool, oldRateKeeper))
        );
    }

    function onAddToken(address pool, address token, address)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        address rateKeeper = _rateKeeper(_quotaKeeper(pool));
        return CallBuilder.build(_addToken(rateKeeper, token, _getRateKeeperType(rateKeeper)));
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function configure(address pool, bytes calldata callData)
        external
        view
        override(AbstractFactory, IFactory)
        returns (Call[] memory)
    {
        address rateKeeper = _rateKeeper(_quotaKeeper(pool));
        bytes4 selector = bytes4(callData);
        if (_isForbiddenConfigurationCall(rateKeeper, selector)) revert ForbiddenConfigurationCallException(selector);
        return CallBuilder.build(Call(rateKeeper, callData));
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _getRateKeeperType(address rateKeeper) internal view returns (bytes32) {
        try IRateKeeper(rateKeeper).contractType() returns (bytes32 type_) {
            return type_;
        } catch {
            return "RK_GAUGE";
        }
    }

    function _isForbiddenConfigurationCall(address rateKeeper, bytes4 selector) internal view returns (bool) {
        if (_getRateKeeperType(rateKeeper) == "RK_GAUGE") {
            return selector == IRateKeeper.addToken.selector || selector == IGaugeV3.addQuotaToken.selector
                || selector == IGaugeV3.setFrozenEpoch.selector || selector == bytes4(keccak256("setController(address)"));
        }
        return selector == IRateKeeper.addToken.selector;
    }

    function _installRateKeeper(address rateKeeper, bytes32 type_) internal view returns (Call[] memory calls) {
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(Call(rateKeeper, abi.encodeCall(IGaugeV3.setFrozenEpoch, false)));
        }

        if (_isVotingContract(rateKeeper)) {
            calls = calls.append(_setVotingContractStatus(rateKeeper, true));
        }
    }

    function _uninstallRateKeeper(address rateKeeper, bytes32 type_) internal view returns (Call[] memory calls) {
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(Call(rateKeeper, abi.encodeCall(IGaugeV3.setFrozenEpoch, true)));
        }

        if (_isVotingContract(rateKeeper)) {
            calls = calls.append(_setVotingContractStatus(rateKeeper, false));
        }
    }

    function _addToken(address rateKeeper, address token, bytes32 type_) internal pure returns (Call memory) {
        return Call(
            rateKeeper,
            type_ == "RK_GAUGE"
                ? abi.encodeCall(IGaugeV3.addQuotaToken, (token, 1, 1))
                : abi.encodeCall(IRateKeeper.addToken, token)
        );
    }
}
