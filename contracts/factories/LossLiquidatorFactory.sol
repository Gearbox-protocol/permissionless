// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IMarketFactory} from "../interfaces/factories/IMarketFactory.sol";
import {ILossLiquidatorFactory} from "../interfaces/factories/ILossLiquidatorFactory.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {AP_LOSS_LIQUIDATOR_FACTORY, DOMAIN_LOSS_LIQUIDATOR} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {AbstractMarketFactory} from "./AbstractMarketFactory.sol";

contract LossLiquidatorFactory is AbstractMarketFactory, ILossLiquidatorFactory {
    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_LOSS_LIQUIDATOR_FACTORY;

    /// @notice Constructor
    /// @param addressProvider_ Address provider contract address
    constructor(address addressProvider_) AbstractFactory(addressProvider_) {}

    // ---------- //
    // DEPLOYMENT //
    // ---------- //

    function deployLossLiquidator(address pool, DeployParams calldata params)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        if (params.postfix == "ALIASED") {
            address decodedACL = abi.decode(params.constructorParams, (address));
            if (decodedACL != _acl(pool)) revert InvalidConstructorParamsException();
        } else {
            _validateDefaultConstructorParams(pool, params.constructorParams);
        }

        address lossLiquidator = _deployLatestPatch({
            contractType: _getContractType(DOMAIN_LOSS_LIQUIDATOR, params.postfix),
            minorVersion: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(msg.sender))
        });

        return DeployResult({
            newContract: lossLiquidator,
            onInstallOps: CallBuilder.build(_authorizeFactory(msg.sender, pool, lossLiquidator))
        });
    }

    // ------------ //
    // MARKET HOOKS //
    // ------------ //

    function onUpdateLossLiquidator(address pool, address, address oldLossLiquidator)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory calls)
    {
        calls = CallBuilder.build(_unauthorizeFactory(msg.sender, pool, oldLossLiquidator));
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
        return CallBuilder.build(Call(_lossLiquidator(pool), callData));
    }

    function emergencyConfigure(address pool, bytes calldata callData)
        external
        view
        override(AbstractFactory, IFactory)
        returns (Call[] memory)
    {
        // TODO: only allow to disable and pause
        return CallBuilder.build(Call(_lossLiquidator(pool), callData));
    }
}
