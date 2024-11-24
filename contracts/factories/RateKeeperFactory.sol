// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IControlledTrait} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IControlledTrait.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";

import {IRateKeeper} from "../interfaces/extensions/IRateKeeper.sol";
import {IMarketHooks} from "../interfaces/factories/IMarketHooks.sol";
import {IRateKeeperFactory} from "../interfaces/factories/IRateKeeperFactory.sol";
import {IMarketConfiguratorFactory} from "../interfaces/IMarketConfiguratorFactory.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {
    DOMAIN_RATE_KEEPER,
    AP_RATE_KEEPER_FACTORY,
    NO_VERSION_CONTROL,
    AP_GEAR_STAKING
} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketHooks} from "./MarketHooks.sol";

contract RateKeeperFactory is AbstractFactory, MarketHooks, IRateKeeperFactory {
    using CallBuilder for Call[];

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_RATE_KEEPER_FACTORY;

    constructor(address addressProvider_) AbstractFactory(addressProvider_) {}

    function deployRateKeeper(address pool, DeployParams calldata params)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        // TODO: replace "GAUGE" with TYPE_POSTFIX_GAUGE
        if (params.postfix == "GAUGE") {
            (address decodedPool, address decodedGearStaking) = abi.decode(params.constructorParams, (address, address));
            if (decodedPool != pool || decodedGearStaking != _getContract(AP_GEAR_STAKING, NO_VERSION_CONTROL)) {
                revert InvalidConstructorParamsException();
            }
        } else if (params.postfix == "TUMBLER") {
            (address decodedQuotaKeeper,) = abi.decode(params.constructorParams, (address, uint256));
            if (decodedQuotaKeeper != _quotaKeeper(pool)) {
                revert InvalidConstructorParamsException();
            }
        } else {
            (address decodedAddressProvider, address decodedQuotaKeeper) =
                abi.decode(params.constructorParams[:64], (address, address));
            if (decodedAddressProvider != addressProvider || decodedQuotaKeeper != _quotaKeeper(pool)) {
                revert InvalidConstructorParamsException();
            }
        }

        address rateKeeper = _deployByDomain({
            domain: DOMAIN_RATE_KEEPER,
            postfix: params.postfix,
            version: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(msg.sender))
        });

        address[] memory accessList = new address[](1);
        accessList[0] = rateKeeper;

        return DeployResult({newContract: rateKeeper, accessList: accessList, onInstallOps: new Call[](0)});
    }

    // ------------ //
    // MARKET HOOKS //
    // ------------ //

    function onCreateMarket(address, address, address, address rateKeeper, address, address)
        external
        view
        override(IMarketHooks, MarketHooks)
        returns (Call[] memory)
    {
        return _installRateKeeper(rateKeeper);
    }

    function onShutdownMarket(address pool) external view override(IMarketHooks, MarketHooks) returns (Call[] memory) {
        return _uninstallRateKeeper(_rateKeeper(pool));
    }

    function onUpdateRateKeeper(address, address newRateKeeper, address oldRateKeeper)
        external
        view
        override(IMarketHooks, MarketHooks)
        returns (Call[] memory)
    {
        return _uninstallRateKeeper(oldRateKeeper).extend(_installRateKeeper(newRateKeeper));
    }

    function onAddToken(address pool, address token, address)
        external
        view
        override(IMarketHooks, MarketHooks)
        returns (Call[] memory)
    {
        address rateKeeper = _rateKeeper(pool);
        return CallBuilder.build(_addToken(rateKeeper, token, _getRateKeeperType(rateKeeper)));
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function configure(address rateKeeper, bytes calldata callData) external view override returns (Call[] memory) {
        bytes4 selector = bytes4(callData);
        // TODO: block activate/deactive (or `setFrozenEpoch`, in the case of gauge)
        if (selector == IControlledTrait.setController.selector || selector == _getAddTokenSelector(rateKeeper)) {
            revert ForbiddenConfigurationCallException(selector);
        }
        return CallBuilder.build(Call({target: rateKeeper, callData: callData}));
    }

    function manage(address, bytes calldata callData) external pure override returns (Call[] memory) {
        // TODO: implement
        revert ForbiddenManagementCallException(bytes4(callData));
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _quotaKeeper(address pool) internal view returns (address) {
        return IPoolV3(pool).poolQuotaKeeper();
    }

    function _rateKeeper(address pool) internal view returns (address) {
        return IPoolQuotaKeeperV3(_quotaKeeper(pool)).gauge();
    }

    function _getRateKeeperType(address rateKeeper) internal view returns (bytes32) {
        try IRateKeeper(rateKeeper).contractType() returns (bytes32 type_) {
            return type_;
        } catch {
            return "RK_GAUGE";
        }
    }

    function _getAddTokenSelector(address rateKeeper) internal view returns (bytes4) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") return IGaugeV3.addQuotaToken.selector;
        if (type_ == "RK_TUMBLER") return ITumblerV3.addToken.selector;
        return IRateKeeper.addToken.selector;
    }

    function _installRateKeeper(address rateKeeper) internal view returns (Call[] memory calls) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(Call(rateKeeper, abi.encodeCall(IGaugeV3.setFrozenEpoch, false)));
        } else if (type_ != "RK_TUMBLER") {
            // TODO: add generic function for all rate keepers (except tumbler apparently)
        }

        if (_isVotingContract(rateKeeper)) {
            calls = calls.append(_setVotingContractStatus(rateKeeper, true));
        }
    }

    function _uninstallRateKeeper(address rateKeeper) internal view returns (Call[] memory calls) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(Call(rateKeeper, abi.encodeCall(IGaugeV3.setFrozenEpoch, true)));
        } else if (type_ != "RK_TUMBLER") {
            // TODO: add generic function for all rate keepers (except tumbler apparently)
        }

        if (_isVotingContract(rateKeeper)) {
            calls = calls.append(_setVotingContractStatus(rateKeeper, false));
        }
    }

    function _addToken(address rateKeeper, address token, bytes32 type_) internal pure returns (Call memory) {
        bytes memory callData;
        if (type_ == "RK_GAUGE") {
            callData = abi.encodeCall(IGaugeV3.addQuotaToken, (token, 1, 1));
        } else if (type_ == "RK_TUMBLER") {
            callData = abi.encodeCall(ITumblerV3.addToken, (token, 1));
        } else {
            callData = abi.encodeCall(IRateKeeper.addToken, token);
        }
        return Call({target: rateKeeper, callData: callData});
    }
}
