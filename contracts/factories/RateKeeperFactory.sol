// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";

import {IRateKeeper} from "../interfaces/extensions/IRateKeeper.sol";
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
        // TODO: okay, make all of them accept pool as first argument - it can be previewed at least

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

        return DeployResult({
            newContract: rateKeeper,
            onInstallOps: CallBuilder.build(_addToAccessList(msg.sender, rateKeeper))
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
        return _installRateKeeper(rateKeeper);
    }

    function onShutdownMarket(address pool)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        return _uninstallRateKeeper(_rateKeeper(_quotaKeeper(pool)));
    }

    function onUpdateRateKeeper(address, address newRateKeeper, address oldRateKeeper)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        return _uninstallRateKeeper(oldRateKeeper).extend(_installRateKeeper(newRateKeeper));
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
        return CallBuilder.build(Call({target: rateKeeper, callData: callData}));
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
        if (selector == bytes4(keccak256("setController(address)"))) return true;

        bytes32 rateKeeperType = _getRateKeeperType(rateKeeper);
        if (rateKeeperType == "RK_GAUGE") {
            return selector == IGaugeV3.addQuotaToken.selector || selector == IGaugeV3.setFrozenEpoch.selector;
        } else if (rateKeeperType == "RK_TUMBLER") {
            return selector == ITumblerV3.addToken.selector;
        } else {
            return selector == IRateKeeper.addToken.selector;
        }
    }

    function _installRateKeeper(address rateKeeper) internal view returns (Call[] memory calls) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(Call(rateKeeper, abi.encodeCall(IGaugeV3.setFrozenEpoch, false)));
        }

        if (_isVotingContract(rateKeeper)) {
            calls = calls.append(_setVotingContractStatus(rateKeeper, true));
        }
    }

    function _uninstallRateKeeper(address rateKeeper) internal view returns (Call[] memory calls) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") {
            calls = CallBuilder.build(Call(rateKeeper, abi.encodeCall(IGaugeV3.setFrozenEpoch, true)));
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
