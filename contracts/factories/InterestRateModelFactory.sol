// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {AbstractFactory} from "./AbstractFactory.sol";
import {IInterestRateModelFactory} from "../interfaces/IInterestRateModelFactory.sol";
import {AP_INTEREST_MODEL_FACTORY, DOMAIN_IRM} from "../libraries/ContractLiterals.sol";
import {DeployResult, Call} from "../interfaces/Types.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

contract InterestRateModelFactory is AbstractFactory, IInterestRateModelFactory {
    // Contract meta data
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_INTEREST_MODEL_FACTORY;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {}

    // @dev Deploy new interest rate model
    // @param acl - ACL address
    // @param postfix - postfix for the interest rate model
    // @param encodedParams - encoded parameters for the interest rate model
    // @return result - deploy result
    function deployInterestRateModel(bytes32 postfix, bytes calldata constructorParams)
        external
        override
        returns (DeployResult memory)
    {
        // Get required addresses from MarketConfigurator
        address acl = IMarketConfigurator(msg.sender).acl();
        // QUESTION: how to add ACL here?
        address model = IBytecodeRepository(bytecodeRepository).deployByDomain(
            DOMAIN_IRM, postfix, version, constructorParams, bytes32(bytes20(msg.sender))
        );

        address[] memory accessList = new address[](1);
        accessList[0] = model;

        return DeployResult({newContract: model, accessList: accessList, onInstallOps: new Call[](0)});
    }

    // @dev Hook which is called when interest rate model is configured
    // @param irm - interest rate model address
    // @param callData - call data to be executed
    // @return calls - array of calls to be executed
    function configure(address irm, bytes calldata callData) external view returns (Call[] memory calls) {
        // TODO: implement
    }
}
