// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {AccountFactoryV3} from "@gearbox-protocol/core-v3/contracts/core/AccountFactoryV3.sol";
import {BotListV3} from "@gearbox-protocol/core-v3/contracts/core/BotListV3.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ICreditFactory} from "../interfaces/ICreditFactory.sol";

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
    AP_CREDIT_FACADE,
    AP_CREDIT_CONFIGURATOR,
    AP_CREDIT_FACTORY,
    AP_WETH_TOKEN,
    AP_BYTECODE_REPOSITORY,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {Call} from "../interfaces/Types.sol";

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
    //
    uint256 debtLimit;
    uint128 minDebt;
    uint128 maxDebt;
    uint16 feeLiquidation;
    uint16 liquidationPremium;
    uint16 feeLiquidationExpired;
    uint16 liquidationPremiumExpired;
}

// CreditFactoryV3 is responsible for deploying the entire credit suite and managing specific management functions.
contract CreditFactoryV3 is AbstractFactory, ICreditFactory {
    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_CREDIT_FACTORY;

    // AccountFactory instance which is used for all deployed creditManagers by this factory
    address public immutable accountFactory;

    // Address of the BotList contract
    address public immutable botList;

    // Address of the WETH token
    address public immutable weth;

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {
        accountFactory = address(new AccountFactoryV3());
        botList = address(new BotListV3());
        weth = IAddressProvider(_addressProvider).getAddressOrRevert(AP_WETH_TOKEN, NO_VERSION_CONTROL);
    }

    /// @notice Creates a new credit suite for the specified pool with provided parameters.
    /// @param pool The address of the pool for which to create the credit suite.
    /// @param encodedParams The encoded deployment parameters for the credit suite.
    /// @return creditManager The address of the deployed credit manager.
    /// @return onInstallOps An array of Call structs representing additional calls to be executed.
    function createCreditSuite(address pool, bytes calldata encodedParams)
        external
        override
        marketConfiguratorOnly
        returns (address creditManager, Call[] memory onInstallOps)
    {
        // Control pool version
        CreditSuiteDeployParams memory params = abi.decode(encodedParams, (CreditSuiteDeployParams));

        address priceOracle = IMarketConfigurator.priceOracles(pool);
        address[] memory emergencyLiquidators = IMarketConfigurator(msg.sender).emergencyLiquidators();

        creditManager =
            _deployCreditManager(pool, priceOracle, params.maxEnabledTokens, params.feeInterest, params.name);

        address creditConfigurator = _deployCreditConfigurator(creditManager);
        address creditFacade = _deployCreditFacade(creditManager, params.degenNFT, params.expirable);

        // Execute on behalf of factory
        ICreditManagerV3(creditManager).setCreditConfigurator(creditConfigurator);

        AccountFactoryV3(accountFactory).addCreditManager(creditManager);
        BotListV3(botList).addCreditManager(creditManager);

        callData = Call.build(_setCreditFacade(creditConfigurator, creditFacade, false));
    }

    /// @notice Single endpoint for configuring credit managers
    /// @dev This function serves as a unified entry point for various configuration operations on credit managers
    /// @param creditManager The address of the credit manager to configure
    /// @param callData Encoded configuration data, specific to the operation being performed
    /// @return calls An array of Call structs representing the configuration operations to be executed
    function configure(address creditManager, bytes calldata callData)
        external
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {
        bytes4 selector = bytes4(callData);
        if (selector == ICreditConfig.deployAdapter.selector) {
            (bytes32 postfix, bytes memory constructorParams) = abi.decode(callData[4:], (bytes32, bytes));

            // TODO: verify, that the first parameter in constructorParams is creditManager
            address newAdapter = IBytecodeRepository(bytecodeRepository).deployByDomain(
                DOMAIN_ADAPTER, postfix, version, constructorParams, bytes32(msg.sender)
            );

            calls = Call.build(_allowAdapter(creditManager, newAdapter));
        } else if (selector == ICreditConfig.deployDegenNFT.selector) {
            (bytes32 postfix, bytes calldata specificParams) = abi.decode(callData[4:], (bytes32, bytes));

            IBytecodeRepository(bytecodeRepository).deployByDomain(
                DOMAIN_DEGEN_NFT, postfix, version, constructorParams, bytes32(msg.sender)
            );
        }

        // QUESTION: mapping for other functions of if..else statements?
    }

    // add as subfuncton of creditManager
    function _configureAdapter(address creditManager, address targetContract, bytes calldata data) internal {
        _ensureRegisteredCreditManager(creditManager);

        address adapter = _getAdapterOrRevert(creditManager, targetContract);
        adapter.functionCall(data);
    }

    function _getAdapterOrRevert(address creditManager, address targetContract) internal view returns (address) {
        address adapter = ICreditManagerV3(creditManager).contractToAdapter(targetContract);
        if (adapter == address(0)) revert AdapterNotInitializedException(creditManager, targetContract);
        return adapter;
    }

    //
    // HOOKS

    function onUpdatePriceOracle(address creditManager, address priceOracle, address prevOracle)
        external
        view
        returns (Call[] memory calls)
    {
        calls = Call.build(_updatePriceOracle(creditManager, priceOracle));
    }

    function onAddEmergencyLiquidator(address creditManager, address liquidator)
        external
        view
        returns (Call[] memory calls)
    {
        calls = Call.build(_addEmergencyLiquidator(creditManager, liquidator));
    }

    function onRemoveEmergencyLiquidator(address liquidator) external view returns (Call[] memory calls) {
        calls = Call.build(_removeEmergencyLiquidator(creditManager, liquidator));
    }

    function onUpdateLossLiquidator(address creditManager, address lossLiquidator)
        external
        view
        returns (Call[] memory calls)
    {
        calls = Call.build(_updateLossLiquidator(pool, type_, params));
    }

    //
    // DEPLOYMENTS

    function _deployCreditManager(
        address marketConfigurator,
        address _pool,
        address _priceOracle,
        uint8 _maxEnabledTokens,
        uint16 _feeInterest,
        string memory _name
    ) internal returns (address) {
        // check prefix
        address underlying = IPoolV3(_pool).asset();

        // TODO: move mapping back to factory
        bytes32 postfix = IBytecodeRepository(bytecodeRepository).hasTokenSpecificPrefix(underlying);

        // CreditManager  constructor parameters:
        //   (
        //     address _pool,
        //     address _accountFactory,
        //     address _priceOracle,
        //     uint8 _maxEnabledTokens,
        //     uint16 _feeInterest,
        //     string memory _name
        //   )
        bytes memory constructorParams =
            abi.encode(_pool, accountFactory, _priceOracle, _maxEnabledTokens, _feeInterest, _name);

        return IBytecodeRepository(bytecodeRepository).deployByDomain(
            DOMAIN_CREDIT_MANAGER, postfix, version, constructorParams, bytes32(marketConfigurator)
        );
    }

    function _deployCreditConfigurator(address creditManager, address marketConfigurator) internal returns (address) {
        bytes memory constructorParams = abi.encode(creditManager);

        return IBytecodeRepository(bytecodeRepository).deploy(
            AP_CREDIT_CONFIGURATOR, version, constructorParams, bytes32(marketConfigurator)
        );
    }

    function _deployCreditFacade(address creditManager, address _degenNFT, bool _expirable, address marketConfigurator)
        internal
        returns (address)
    {
        bytes memory constructorParams = abi.encode(creditManager, botList, weth, _degenNFT, _expirable);

        return IBytecodeRepository(bytecodeRepository).deploy(
            AP_CREDIT_FACADE, version, constructorParams, bytes32(marketConfigurator)
        );
    }

    //
    // Function Call Generators
    //
    function _creditConfigurator(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).creditConfigurator();
    }

    function _setCreditFacade(address creditManager, address newCreditFacade, bool migrateParams)
        internal
        view
        returns (Call memory call)
    {
        call = Call({
            target: _creditConfigurator(creditManager),
            callData: abi.encodeCall(ICreditConfiguratorV3.setCreditFacade, (newCreditFacade, migrateParams))
        });
    }

    function _addEmergencyLiquidator(address creditManager, address liquidator)
        internal
        view
        returns (Call memory call)
    {
        call = Call({
            target: _creditConfigurator(creditManager),
            callData: abi.encodeCall(ICreditConfigurator.addEmergencyLiquidator, liquidator)
        });
    }

    function _removeEmergencyLiquidator(address creditManager, address liquidator)
        internal
        view
        returns (Call memory call)
    {
        call = Call({
            target: _creditConfigurator(creditManager),
            callData: abi.encodeCall(ICreditConfigurator.removeEmergencyLiquidator, liquidator)
        });
    }

    function _updateLossLiquidator(address creditManager, address lossLiquidator)
        internal
        view
        returns (Call memory call)
    {
        call = Call({
            target: _creditConfigurator(creditManager),
            callData: abi.encodeCall(ICreditConfigurator.updateLossLiquidator, lossLiquidator)
        });
    }

    function _updatePriceOracle(address creditManager, address priceOracle) internal view returns (Call memory call) {
        call = Call({
            target: _creditConfigurator(creditManager),
            callData: abi.encodeCall(ICreditConfigurator.setPriceOracle, priceOracle)
        });
    }

    function _allowAdapter(address creditManager, address newAdapter) internal view returns (Call memory call) {
        call = Call({
            target: _creditConfigurator(creditManager),
            callData: abi.encodeCall(ICreditConfigurator.allowAdapter, newAdapter)
        });
    }
}
