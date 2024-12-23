// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {ICreditFactory} from "../interfaces/factories/ICreditFactory.sol";
import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {Call, DeployParams, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {
    DOMAIN_ADAPTER,
    DOMAIN_CREDIT_MANAGER,
    AP_CREDIT_CONFIGURATOR,
    AP_CREDIT_FACADE,
    AP_CREDIT_FACTORY,
    AP_WETH_TOKEN,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";

struct CreditManagerParams {
    address accountFactory;
    uint8 maxEnabledTokens;
    uint16 feeInterest;
    uint16 feeLiquidation;
    uint16 liquidationPremium;
    uint16 feeLiquidationExpired;
    uint16 liquidationPremiumExpired;
    uint128 minDebt;
    uint128 maxDebt;
    string name;
}

struct CreditFacadeParams {
    address botList;
    address degenNFT;
    bool expirable;
}

interface IConfigureActions {
    function upgradeCreditConfigurator() external;
    function upgradeCreditFacade(CreditFacadeParams calldata params) external;
    function allowAdapter(DeployParams calldata params) external;
    function forbidAdapter(address adapter) external;
    function setFees(
        uint16 feeLiquidation,
        uint16 liquidationPremium,
        uint16 feeLiquidationExpired,
        uint16 liquidationPremiumExpired
    ) external;
    function setMaxDebtPerBlockMultiplier(uint8 newMaxDebtLimitPerBlockMultiplier) external;
    function addCollateralToken(address token, uint16 liquidationThreshold) external;
    function rampLiquidationThreshold(
        address token,
        uint16 liquidationThresholdFinal,
        uint40 rampStart,
        uint24 rampDuration
    ) external;
    function forbidToken(address token) external;
    function allowToken(address token) external;
    function setExpirationDate(uint40 newExpirationDate) external;
    function pause() external;
    function unpause() external;
}

interface IEmergencyConfigureActions {
    function forbidAdapter(address adapter) external;
    function forbidToken(address token) external;
    function forbidBorrowing() external;
    function pause() external;
}

contract CreditFactory is AbstractFactory, ICreditFactory {
    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_CREDIT_FACTORY;

    /// @notice Address of the WETH token
    address public immutable weth;

    /// @notice Constructor
    /// @param addressProvider_ Address provider contract address
    constructor(address addressProvider_) AbstractFactory(addressProvider_) {
        // TODO: introduce some kind of `StuffRegister` for account factories, bot lists and degen NFTs
        weth = _tryGetContract(AP_WETH_TOKEN, NO_VERSION_CONTROL);
    }

    // ---------- //
    // DEPLOYMENT //
    // ---------- //

    function deployCreditSuite(address pool, bytes calldata encodedParams)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address priceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);
        address lossLiquidator = IContractsRegister(contractsRegister).getLossLiquidator(pool);

        (CreditManagerParams memory params, CreditFacadeParams memory facadeParams) =
            abi.decode(encodedParams, (CreditManagerParams, CreditFacadeParams));

        address creditManager = _deployCreditManager(msg.sender, pool, priceOracle, params);
        address creditConfigurator = _deployCreditConfigurator(msg.sender, creditManager);
        address creditFacade = _deployCreditFacade(msg.sender, creditManager, facadeParams);

        ICreditManagerV3(creditManager).setCreditConfigurator(creditConfigurator);

        return DeployResult({
            newContract: creditManager,
            onInstallOps: CallBuilder.build(
                _addToAccessList(msg.sender, creditConfigurator),
                _addToAccessList(msg.sender, creditFacade),
                _setCreditFacade(creditConfigurator, creditFacade, false),
                _setLossLiquidator(creditConfigurator, lossLiquidator),
                _setDebtLimits(creditConfigurator, params.minDebt, params.maxDebt)
            )
        });
    }

    // ------------ //
    // CREDIT HOOKS //
    // ------------ //

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

    function configure(address creditManager, bytes calldata callData)
        external
        override(AbstractFactory, IFactory)
        onlyMarketConfigurators
        returns (Call[] memory)
    {
        bytes4 selector = bytes4(callData);
        if (selector == IConfigureActions.upgradeCreditConfigurator.selector) {
            address creditConfigurator = _creditConfigurator(creditManager);
            address newCreditConfigurator = _deployCreditConfigurator(msg.sender, creditManager);
            return CallBuilder.build(
                _upgradeCreditConfigurator(creditConfigurator, newCreditConfigurator),
                _removeFromAccessList(msg.sender, creditConfigurator),
                _addToAccessList(msg.sender, newCreditConfigurator)
            );
        } else if (selector == IConfigureActions.upgradeCreditFacade.selector) {
            CreditFacadeParams memory params = abi.decode(callData[4:], (CreditFacadeParams));
            address creditFacade = _creditFacade(creditManager);
            address newCreditFacade = _deployCreditFacade(msg.sender, creditManager, params);
            return CallBuilder.build(
                _setCreditFacade(_creditConfigurator(creditManager), newCreditFacade, true),
                _removeFromAccessList(msg.sender, creditFacade),
                _addToAccessList(msg.sender, newCreditFacade)
            );
        } else if (selector == IConfigureActions.allowAdapter.selector) {
            DeployParams memory params = abi.decode(callData[4:], (DeployParams));
            address adapter = _deployAdapter(msg.sender, creditManager, params);
            return CallBuilder.build(
                _addToAccessList(msg.sender, adapter), _allowAdapter(_creditConfigurator(creditManager), adapter)
            );
        } else if (selector == IConfigureActions.forbidAdapter.selector) {
            address adapter = abi.decode(callData[4:], (address));
            return CallBuilder.build(
                _removeFromAccessList(msg.sender, adapter), _forbidAdapter(_creditConfigurator(creditManager), adapter)
            );
        } else if (
            selector == IConfigureActions.setFees.selector
                || selector == IConfigureActions.setMaxDebtPerBlockMultiplier.selector
                || selector == IConfigureActions.addCollateralToken.selector
                || selector == IConfigureActions.rampLiquidationThreshold.selector
                || selector == IConfigureActions.forbidToken.selector || selector == IConfigureActions.allowToken.selector
                || selector == IConfigureActions.setExpirationDate.selector
        ) {
            return CallBuilder.build(Call(_creditConfigurator(creditManager), callData));
        } else if (selector == IConfigureActions.pause.selector || selector == IConfigureActions.unpause.selector) {
            return CallBuilder.build(Call(_creditFacade(creditManager), callData));
        } else {
            revert ForbiddenConfigurationCallException(selector);
        }
    }

    function emergencyConfigure(address creditManager, bytes calldata callData)
        external
        view
        override(AbstractFactory, IFactory)
        returns (Call[] memory)
    {
        bytes4 selector = bytes4(callData);
        if (selector == IEmergencyConfigureActions.forbidAdapter.selector) {
            address adapter = abi.decode(callData[4:], (address));
            return CallBuilder.build(
                _removeFromAccessList(msg.sender, adapter), _forbidAdapter(_creditConfigurator(creditManager), adapter)
            );
        } else if (
            selector == IEmergencyConfigureActions.forbidBorrowing.selector
                || selector == IEmergencyConfigureActions.forbidToken.selector
        ) {
            return CallBuilder.build(Call(_creditConfigurator(creditManager), callData));
        } else if (selector == IEmergencyConfigureActions.pause.selector) {
            return CallBuilder.build(Call(_creditFacade(creditManager), callData));
        } else {
            revert ForbiddenEmergencyConfigurationCallException(selector);
        }
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _deployCreditManager(
        address marketConfigurator,
        address pool,
        address priceOracle,
        CreditManagerParams memory params
    ) internal returns (address) {
        bytes32 postfix = _getTokenSpecificPostfix(IPoolV3(pool).asset());

        // TODO: ensure that account factory is registered, add manager to it
        bytes memory constructorParams = abi.encode(
            pool,
            params.accountFactory,
            priceOracle,
            params.maxEnabledTokens,
            params.feeInterest,
            params.feeLiquidation,
            params.liquidationPremium,
            params.feeLiquidationExpired,
            params.liquidationPremiumExpired,
            params.name
        );

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

    function _deployCreditFacade(address marketConfigurator, address creditManager, CreditFacadeParams memory params)
        internal
        returns (address)
    {
        address acl = IMarketConfigurator(marketConfigurator).acl();
        // TODO: ensure that botList is registered, coincides with the previous one, add manager to it
        // TODO: ensure that degenNFT is registered, add facade to it
        bytes memory constructorParams =
            abi.encode(acl, creditManager, params.botList, weth, params.degenNFT, params.expirable);

        return _deploy({
            contractType: AP_CREDIT_FACADE,
            version: version,
            constructorParams: constructorParams,
            salt: bytes32(bytes20(marketConfigurator))
        });
    }

    function _deployAdapter(address marketConfigurator, address creditManager, DeployParams memory params)
        internal
        returns (address)
    {
        address decodedCreditManager = address(bytes20(bytes32(params.constructorParams)));
        if (decodedCreditManager != creditManager) revert InvalidConstructorParamsException();

        // NOTE: unlike other contracts, this might be deployed multiple times, so using the same salt
        // can be an issue. Same thing can happen to rate keepers, IRMs, etc.
        return _deployByDomain({
            domain: DOMAIN_ADAPTER,
            postfix: params.postfix,
            version: version,
            constructorParams: params.constructorParams,
            salt: bytes32(bytes20(marketConfigurator))
        });
    }

    function _creditConfigurator(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).creditConfigurator();
    }

    function _creditFacade(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).creditFacade();
    }

    function _upgradeCreditConfigurator(address creditConfigurator, address newCreditConfigurator)
        internal
        pure
        returns (Call memory)
    {
        return Call(
            creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.upgradeCreditConfigurator, (newCreditConfigurator))
        );
    }

    function _setCreditFacade(address creditConfigurator, address creditFacade, bool migrateParams)
        internal
        pure
        returns (Call memory)
    {
        return Call(
            creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.setCreditFacade, (creditFacade, migrateParams))
        );
    }

    function _setPriceOracle(address creditConfigurator, address priceOracle) internal pure returns (Call memory) {
        return Call(creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.setPriceOracle, priceOracle));
    }

    function _setLossLiquidator(address creditConfigurator, address lossLiquidator)
        internal
        pure
        returns (Call memory)
    {
        return Call(creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.setLossLiquidator, lossLiquidator));
    }

    function _allowAdapter(address creditConfigurator, address adapter) internal pure returns (Call memory) {
        return Call(creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.allowAdapter, adapter));
    }

    function _forbidAdapter(address creditConfigurator, address adapter) internal pure returns (Call memory) {
        return Call(creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.forbidAdapter, adapter));
    }

    function _setFees(
        address creditConfigurator,
        uint16 feeLiquidation,
        uint16 liquidationPremium,
        uint16 feeLiquidationExpired,
        uint16 liquidationPremiumExpired
    ) internal pure returns (Call memory) {
        return Call(
            creditConfigurator,
            abi.encodeCall(
                ICreditConfiguratorV3.setFees,
                (feeLiquidation, liquidationPremium, feeLiquidationExpired, liquidationPremiumExpired)
            )
        );
    }

    function _setDebtLimits(address creditConfigurator, uint128 minDebt, uint128 maxDebt)
        internal
        pure
        returns (Call memory)
    {
        return Call(creditConfigurator, abi.encodeCall(ICreditConfiguratorV3.setDebtLimits, (minDebt, maxDebt)));
    }
}
