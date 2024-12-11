// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IFactory} from "../interfaces/factories/IFactory.sol";
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
            // TODO: add checks for other kinds of loss liquidators
        }

        address lossLiquidator = _deployByDomain({
            domain: DOMAIN_LOSS_LIQUIDATOR,
            postfix: params.postfix,
            version: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(msg.sender))
        });

        return DeployResult({
            newContract: lossLiquidator,
            onInstallOps: CallBuilder.build(_addToAccessList(msg.sender, lossLiquidator))
        });
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
        return CallBuilder.build(Call({target: _lossLiquidator(pool), callData: callData}));
    }
}
