// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {ILossLiquidatorFactory} from "../interfaces/ILossLiquidatorFactory.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {AP_LOSS_LIQUIDATOR_FACTORY, DOMAIN_LOSS_LIQUIDATOR} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketHooks} from "./MarketHooks.sol";

contract LossLiquidatorFactory is ILossLiquidatorFactory, AbstractFactory, MarketHooks {
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_LOSS_LIQUIDATOR_FACTORY;

    constructor(address addressProvider_) AbstractFactory(addressProvider_) {}

    function deployLossLiquidator(address pool, DeployParams calldata params)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        // QUESTION: what's the default postfix?
        if (params.postfix == "") {
            address decodedACL = abi.decode(params.constructorParams, (address));
            if (decodedACL != IPoolV3(pool).acl()) revert InvalidConstructorParamsException();
        } else {
            // TODO: add checks for other kinds of loss liquidators
        }

        address lossLiquidator = _deployByDomain({
            domain: DOMAIN_LOSS_LIQUIDATOR,
            postfix: params.postfix,
            version_: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(msg.sender))
        });

        address[] memory accessList = new address[](1);
        accessList[0] = lossLiquidator;

        return DeployResult({newContract: lossLiquidator, accessList: accessList, onInstallOps: new Call[](0)});
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function configure(address lossLiquidator, bytes calldata data)
        external
        view
        override
        onlyMarketConfigurators
        returns (Call[] memory)
    {
        return CallBuilder.build(Call({target: lossLiquidator, callData: data}));
    }

    function manage(address, bytes calldata callData)
        external
        override
        onlyMarketConfigurators
        returns (Call[] memory)
    {
        // TODO: implement
        revert ForbiddenManagementCall(bytes4(callData));
    }
}
