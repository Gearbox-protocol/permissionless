// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {AccountFactoryV3} from "@gearbox-protocol/core-v3/contracts/core/AccountFactoryV3.sol";
import {BotListV3} from "@gearbox-protocol/core-v3/contracts/core/BotListV3.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ICreditFactory} from "../interfaces/factories/ICreditFactory.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {CreditManagerV3} from "@gearbox-protocol/core-v3/contracts/credit/CreditManagerV3.sol";
import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {
    DOMAIN_CREDIT_MANAGER,
    DOMAIN_ADAPTER,
    DOMAIN_DEGEN_NFT,
    AP_CREDIT_FACADE,
    AP_CREDIT_CONFIGURATOR,
    AP_CREDIT_FACTORY,
    AP_WETH_TOKEN,
    AP_BYTECODE_REPOSITORY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";
import {CallBuilder} from "../libraries/CallBuilder.sol";

interface ICreditConfig {
    function deployAdapter(bytes32 postfix, bytes calldata constructorParams) external;

    function deployDegenNFT(bytes32 postfix, bytes calldata specificParams) external;
}

struct CreditSuiteDeployParams {
    uint8 maxEnabledTokens;
    uint16 feeInterest;
    string name;
    address degenNFT;
    bool expirable;
    uint256 debtLimit;
    uint128 minDebt;
    uint128 maxDebt;
    uint16 feeLiquidation;
    uint16 liquidationPremium;
    uint16 feeLiquidationExpired;
    uint16 liquidationPremiumExpired;
}

// CreditFactoryV3 is responsible for deploying the entire credit suite and managing specific management functions.
contract CreditFactory is AbstractFactory, ICreditFactory {
    using CallBuilder for Call;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_CREDIT_FACTORY;

    // AccountFactory instance which is used for all deployed creditManagers by this factory
    address public immutable accountFactory;

    // Address of the BotList contract
    address public immutable botList;

    // Address of the WETH token
    address public immutable weth;

    constructor(address addressProvider_) AbstractFactory(addressProvider_) {
        // shouldn't factory be the owner?
        // FIXME: all credit factories of version 3_1x should be able to access these two contracts
        accountFactory = address(new AccountFactoryV3(msg.sender));
        botList = address(new BotListV3(msg.sender));

        try IAddressProvider(addressProvider).getAddressOrRevert(AP_WETH_TOKEN, NO_VERSION_CONTROL) returns (
            address addr
        ) {
            weth = addr;
        } catch {
            weth = address(0);
        }
    }

    // ----------- //
    // DEPLOYMENTS //
    // ----------- //

    /// @notice Deploys a new credit suite for the specified pool with provided parameters.
    /// @param pool The address of the pool for which to create the credit suite.
    /// @param encodedParams The encoded deployment parameters for the credit suite.
    /// @return creditManager The address of the deployed credit manager.
    function deployCreditSuite(address pool, bytes calldata encodedParams)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        // Control pool version
        CreditSuiteDeployParams memory params = abi.decode(encodedParams, (CreditSuiteDeployParams));

        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address priceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);

        address creditManager = _deployCreditManager({
            marketConfigurator: msg.sender,
            pool: pool,
            priceOracle: priceOracle,
            maxEnabledTokens: params.maxEnabledTokens,
            feeInterest: params.feeInterest,
            name: params.name
        });

        address creditConfigurator =
            _deployCreditConfigurator({marketConfigurator: msg.sender, creditManager: creditManager});

        // QUESTION: can we set degenNFT to address(0) and  update it later?
        // QUESTION: can we remove expirable parameter and update it later?
        address creditFacade = _deployCreditFacade({
            marketConfigurator: msg.sender,
            creditManager: creditManager,
            degenNFT: params.degenNFT,
            expirable: params.expirable
        });

        // Execute on behalf of factory
        ICreditManagerV3(creditManager).setCreditConfigurator(creditConfigurator);

        AccountFactoryV3(accountFactory).addCreditManager(creditManager);
        BotListV3(botList).approveCreditManager(creditManager);

        // TODO: add to onInstallOpps setLossLiquidator and addEmergencyLiquidator
        // address[] memory emergencyLiquidators = IMarketConfigurator(msg.sender).emergencyLiquidators();

        address[] memory accessList = new address[](1);
        accessList[0] = creditConfigurator;

        return DeployResult({
            newContract: creditManager,
            accessList: accessList,
            onInstallOps: CallBuilder.build(_setCreditFacade(creditConfigurator, creditFacade, false))
        });
    }

    // ------------------ //
    // CREDIT SUITE HOOKS //
    // ------------------ //

    // FIXME: okay, these really are market hooks

    function onUpdatePriceOracle(address creditManager, address newPriceOracle, address)
        external
        view
        override
        returns (Call[] memory)
    {
        return CallBuilder.build(_setPriceOracle(_creditConfigurator(creditManager), newPriceOracle));
    }

    function onUpdateLossLiquidator(address creditManager, address newLossLiquidator, address)
        external
        view
        override
        returns (Call[] memory)
    {
        return CallBuilder.build(_setLossLiquidator(_creditConfigurator(creditManager), newLossLiquidator));
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    /// @notice Single endpoint for configuring credit managers
    /// @dev This function serves as a unified entry point for various configuration operations on credit managers
    /// @param creditManager The address of the credit manager to configure
    /// @param callData Encoded configuration data, specific to the operation being performed
    /// @return calls An array of Call structs representing the configuration operations to be executed
    function configure(address creditManager, bytes calldata callData)
        external
        override
        onlyMarketConfigurators
        returns (Call[] memory calls)
    {
        bytes4 selector = bytes4(callData);
        if (selector == ICreditConfig.deployAdapter.selector) {
            (bytes32 postfix, bytes memory constructorParams) = abi.decode(callData[4:], (bytes32, bytes));

            // TODO: verify, that the first parameter in constructorParams is creditManager
            address newAdapter = IBytecodeRepository(bytecodeRepository).deployByDomain(
                DOMAIN_ADAPTER, postfix, version, constructorParams, bytes32(bytes20(msg.sender))
            );

            calls = CallBuilder.build(_allowAdapter(creditManager, newAdapter));
        } else if (selector == ICreditConfig.deployDegenNFT.selector) {
            (bytes32 postfix, bytes memory constructorParams) = abi.decode(callData[4:], (bytes32, bytes));

            IBytecodeRepository(bytecodeRepository).deployByDomain(
                DOMAIN_DEGEN_NFT, postfix, version, constructorParams, bytes32(bytes20(msg.sender))
            );
        }

        // QUESTION: mapping for other functions of if..else statements?
    }

    function manage(address, bytes calldata callData)
        external
        view
        override
        onlyMarketConfigurators
        returns (Call[] memory)
    {
        // TODO: implement
        revert ForbiddenManagementCallException(bytes4(callData));
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _deployCreditManager(
        address marketConfigurator,
        address pool,
        address priceOracle,
        uint8 maxEnabledTokens,
        uint16 feeInterest,
        string memory name
    ) internal returns (address) {
        bytes32 postfix = IBytecodeRepository(bytecodeRepository).getTokenSpecificPostfix(IPoolV3(pool).asset());

        bytes memory constructorParams =
            abi.encode(pool, accountFactory, priceOracle, maxEnabledTokens, feeInterest, name);

        return _deployByDomain({
            domain: DOMAIN_CREDIT_MANAGER,
            postfix: postfix,
            version: version,
            constructorParams: constructorParams,
            salt: bytes32(bytes20(marketConfigurator))
        });
    }

    function _deployCreditConfigurator(address marketConfigurator, address creditManager) internal returns (address) {
        bytes memory constructorParams = abi.encode(creditManager);

        return _deploy({
            contractType: AP_CREDIT_CONFIGURATOR,
            version: version,
            constructorParams: constructorParams,
            salt: bytes32(bytes20(marketConfigurator))
        });
    }

    function _deployCreditFacade(address marketConfigurator, address creditManager, address degenNFT, bool expirable)
        internal
        returns (address)
    {
        bytes memory constructorParams = abi.encode(creditManager, botList, weth, degenNFT, expirable);

        return _deploy({
            contractType: AP_CREDIT_FACADE,
            version: version,
            constructorParams: constructorParams,
            salt: bytes32(bytes20(marketConfigurator))
        });
    }

    function _creditConfigurator(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).creditConfigurator();
    }

    function _setCreditFacade(address creditConfigurator, address creditFacade, bool migrateParams)
        internal
        pure
        returns (Call memory)
    {
        return Call({
            target: creditConfigurator,
            callData: abi.encodeCall(ICreditConfiguratorV3.setCreditFacade, (creditFacade, migrateParams))
        });
    }

    function _setPriceOracle(address creditConfigurator, address priceOracle) internal pure returns (Call memory) {
        return Call({
            target: creditConfigurator,
            callData: abi.encodeCall(ICreditConfiguratorV3.setPriceOracle, priceOracle)
        });
    }

    function _setLossLiquidator(address creditConfigurator, address lossLiquidator)
        internal
        pure
        returns (Call memory)
    {
        return Call({
            target: creditConfigurator,
            callData: abi.encodeCall(ICreditConfiguratorV3.setLossLiquidator, lossLiquidator)
        });
    }

    function _allowAdapter(address creditConfigurator, address adapter) internal pure returns (Call memory) {
        return Call({target: creditConfigurator, callData: abi.encodeCall(ICreditConfiguratorV3.allowAdapter, adapter)});
    }
}
