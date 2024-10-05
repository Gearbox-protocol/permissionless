// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPriceOracleV3, PriceFeedParams} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";
import {IControlledTrait} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IControlledTrait.sol";
import {IPriceFeed, IUpdatablePriceFeed} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IPriceFeed.sol";
import "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

import {PERCENTAGE_FACTOR} from "@gearbox-protocol/core-v3/contracts/libraries/Constants.sol";

import {IACLExt} from "../interfaces/extensions/IACLExt.sol";
import {IContractsRegisterExt} from "../interfaces/extensions/IContractsRegisterExt.sol";
import {IRateKeeperExt} from "../interfaces/extensions/IRateKeeperExt.sol";
import {IVotingContractExt} from "../interfaces/extensions/IVotingContractExt.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IConfiguratorFactory} from "../interfaces/IConfiguratorFactory.sol";
import {IContractsFactory} from "../interfaces/IContractsFactory.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IPriceFeedStore} from "../interfaces/IPriceFeedStore.sol";

import {AP_CONTRACTS_FACTORY, AP_PRICE_FEED_STORE} from "../libraries/ContractLiterals.sol";
import {NestedPriceFeeds} from "../libraries/NestedPriceFeeds.sol";

// TODO:
// - zappers management
// - degen NFT management
// - migration to new market configurator
// - rescue

/// @title Market configurator
contract MarketConfigurator is Ownable, IMarketConfigurator {
    using Address for address;
    using SafeERC20 for IERC20;
    using NestedPriceFeeds for IPriceFeed;
    using EnumerableSet for EnumerableSet.AddressSet;

    address public immutable configuratorFactory;
    address public immutable addressProvider;
    address public immutable acl;
    address public immutable contractsRegister;
    address public immutable treasury;

    mapping(address pool => address) public override priceOracles;
    mapping(address pool => address) public override lossLiquidators;
    address public override controller;
    EnumerableSet.AddressSet internal _emergencyLiquidators;

    // ------ //
    // ERRORS //
    // ------ //

    error CantRemoveNonEmptyMarketException(address pool);

    error CantRemoveNonEmptyCreditSuiteException(address creditManager);

    error RampDurationTooShortException();

    error ExpirationDateTooSoonException();

    error PriceFeedNotAllowedException(address token, address priceFeed);

    error AdapterNotInitializedException(address creditManager, address targetContract);

    error LossLiquidatorNotInitializedException(address pool);

    error ControllerNotInitializedException();

    error ForbiddenConfigurationCallException(address target, bytes4 selector);

    // ----------- //
    // CONSTRUCTOR //
    // ----------- //

    constructor(address addressProvider_, address acl_, address contractsRegister_, address treasury_) {
        configuratorFactory = msg.sender;
        addressProvider = addressProvider_;
        acl = acl_;
        contractsRegister = contractsRegister_;
        treasury = treasury_;
    }

    function emergencyLiquidators() external view override returns (address[] memory) {
        return _emergencyLiquidators.values();
    }

    // --------------- //
    // POOL MANAGEMENT //
    // --------------- //

    struct MarketParams {
        bytes poolParams;
        bytes priceOracleParams;
        bytes32 irmType;
        bytes irmParams;
        bytes32 rateKeeperType;
        bytes rateKeeperParams;
    }

    function createMarket(address underlying, address underlyingPriceFeed, bytes calldata encodedParams)
        external
        onlyOwner
        returns (address)
    {
        uint32 stalenessPeriod = _ensureAllowedPriceFeed(underlying, underlyingPriceFeed);
        MarketParams memory params = abi.decode(encodedParams, (MarketParams));

        address irm = _deployInterestRateModel(params.irmType, params.irmParams);
        (address pool, address quotaKeeper) =
            _contractsFactory().deployPool(acl, contractsRegister, underlying, treasury, irm, params.poolParams);
        address rateKeeper = _deployRateKeeper(pool, params.rateKeeperType, params.rateKeeperParams);
        address priceOracle = _deployPriceOracle(acl, params.priceOracleParams);

        IContractsRegisterExt(contractsRegister).addPool(pool);

        IPoolV3(pool).setPoolQuotaKeeper(quotaKeeper);
        _installRateKeeper(quotaKeeper, rateKeeper);

        if (IERC20(underlying).balanceOf(address(this)) < 1e5) revert InsufficientBalanceException();
        IERC20(underlying).forceApprove(pool, 1e5);
        IPoolV3(pool).deposit(1e5, address(0xdead));

        priceOracles[pool] = priceOracle;
        if (_getPrice(underlyingPriceFeed) == 0) revert IncorrectPriceException();
        _setPriceFeed(priceOracle, underlying, underlyingPriceFeed, stalenessPeriod, false);

        address controller_ = controller;
        if (controller_ != address(0)) {
            _setController(irm, controller_);
            _setController(pool, controller_);
            _setController(quotaKeeper, controller_);
            _setController(rateKeeper, controller_);
            _setController(priceOracle, controller_);
        }

        return pool;
    }

    function removeMarket(address pool) external onlyOwner {
        _ensureRegisteredPool(pool);

        if (IPoolV3(pool).totalBorrowed() != 0 || _creditManagers(pool).length != 0) {
            revert CantRemoveNonEmptyMarketException(pool);
        }

        _uninstallRateKeeper(_rateKeeper(_quotaKeeper(pool)));
        _setTotalDebtLimit(pool, 0);
        _setWithdrawFee(pool, 0);
        IContractsRegisterExt(contractsRegister).removePool(pool);
    }

    function setTotalDebtLimit(address pool, uint256 newLimit) external onlyOwner {
        _ensureRegisteredPool(pool);

        _setTotalDebtLimit(pool, newLimit);
    }

    function setWithdrawFee(address pool, uint256 newWithdrawFee) external onlyOwner {
        _ensureRegisteredPool(pool);

        _setWithdrawFee(pool, newWithdrawFee);
    }

    function addToken(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        uint32 stalenessPeriod = _ensureAllowedPriceFeed(token, priceFeed);
        _setPriceFeed(priceOracles[pool], token, priceFeed, stalenessPeriod, false);

        address rateKeeper = _rateKeeper(_quotaKeeper(pool));
        _addToken(rateKeeper, token, _getRateKeeperType(rateKeeper));
    }

    function setTokenLimit(address pool, address token, uint96 limit) external onlyOwner {
        _ensureRegisteredPool(pool);

        IPoolQuotaKeeperV3(_quotaKeeper(pool)).setTokenLimit(token, limit);
    }

    function setTokenQuotaIncreaseFee(address pool, address token, uint16 fee) external onlyOwner {
        _ensureRegisteredPool(pool);

        IPoolQuotaKeeperV3(_quotaKeeper(pool)).setTokenQuotaIncreaseFee(token, fee);
    }

    function _setTotalDebtLimit(address pool, uint256 newLimit) internal {
        IPoolV3(pool).setTotalDebtLimit(newLimit);
    }

    function _setWithdrawFee(address pool, uint256 newWithdrawFee) internal {
        IPoolV3(pool).setWithdrawFee(newWithdrawFee);
    }

    // ----------------------- //
    // CREDIT SUITE MANAGEMENT //
    // ----------------------- //

    struct CreditSuiteParams {
        uint256 debtLimit;
        uint128 minDebt;
        uint128 maxDebt;
        uint16 feeLiquidation;
        uint16 liquidationPremium;
        uint16 feeLiquidationExpired;
        uint16 liquidationPremiumExpired;
        bytes managerParams;
        bytes configuratorParams;
        bytes facadeParams;
    }

    function createCreditSuite(address pool, bytes calldata encodedParams) external onlyOwner returns (address) {
        _ensureRegisteredPool(pool);
        CreditSuiteParams memory params = abi.decode(encodedParams, (CreditSuiteParams));

        address creditManager = _contractsFactory().deployCreditManager(pool, priceOracles[pool], params.managerParams);
        address creditConfigurator = _deployCreditConfigurator(creditManager, params.configuratorParams);
        address creditFacade = _deployCreditFacade(creditManager, params.facadeParams);

        ICreditManagerV3(creditManager).setCreditConfigurator(creditConfigurator);
        _setCreditFacade(creditConfigurator, creditFacade, false);

        IContractsRegisterExt(contractsRegister).addCreditManager(creditManager);
        _setCreditManagerDebtLimit(pool, creditManager, params.debtLimit);
        IPoolQuotaKeeperV3(_quotaKeeper(pool)).addCreditManager(creditManager);
        IConfiguratorFactory(configuratorFactory).addCreditManagerToAccountFactory(creditManager);
        IConfiguratorFactory(configuratorFactory).addCreditManagerToBotList(creditManager);

        _setFees(
            creditConfigurator,
            params.feeLiquidation,
            params.liquidationPremium,
            params.feeLiquidationExpired,
            params.liquidationPremiumExpired
        );
        ICreditConfiguratorV3(creditConfigurator).setDebtLimits(params.minDebt, params.maxDebt);

        address lossLiquidator = lossLiquidators[pool];
        if (lossLiquidator != address(0)) _setLossLiquidator(creditConfigurator, lossLiquidator);

        EnumerableSet.AddressSet storage emergencyLiquidators_ = _emergencyLiquidators;
        uint256 numLiquidators = emergencyLiquidators_.length();
        for (uint256 i; i < numLiquidators; ++i) {
            _addEmergencyLiquidator(creditConfigurator, emergencyLiquidators_.at(i));
        }

        address controller_ = controller;
        if (controller_ != address(0)) _setController(creditConfigurator, controller_);

        return creditManager;
    }

    function removeCreditSuite(address creditManager) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address pool = _pool(creditManager);
        if (IPoolV3(pool).creditManagerBorrowed(creditManager) != 0) {
            revert CantRemoveNonEmptyCreditSuiteException(creditManager);
        }

        _setCreditManagerDebtLimit(pool, creditManager, 0);
        IContractsRegisterExt(contractsRegister).removeCreditManager(creditManager);
    }

    function setCreditFacade(address creditManager, bytes calldata params) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address creditFacade = _deployCreditFacade(creditManager, params);
        _setCreditFacade(_creditConfigurator(creditManager), creditFacade, true);
    }

    function setCreditConfigurator(address creditManager, bytes calldata params) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address creditConfigurator = _deployCreditConfigurator(creditManager, params);
        ICreditConfiguratorV3(_creditConfigurator(creditManager)).upgradeCreditConfigurator(creditConfigurator);

        address controller_ = controller;
        if (controller_ != address(0)) _setController(creditConfigurator, controller_);
    }

    function setCreditManagerDebtLimit(address creditManager, uint256 newLimit) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        _setCreditManagerDebtLimit(_pool(creditManager), creditManager, newLimit);
    }

    function setMaxDebtPerBlockMultiplier(address creditManager, uint8 multiplier) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        ICreditConfiguratorV3(_creditConfigurator(creditManager)).setMaxDebtPerBlockMultiplier(multiplier);
    }

    function addCollateralToken(address creditManager, address token, uint16 lt) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        ICreditConfiguratorV3(_creditConfigurator(creditManager)).addCollateralToken(token, lt);
    }

    function rampLiquidationThreshold(
        address creditManager,
        address token,
        uint16 ltFinal,
        uint40 rampStart,
        uint24 rampDuration
    ) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);
        if (rampDuration < 2 days && _quota(_pool(creditManager), token) != 0) revert RampDurationTooShortException();

        ICreditConfiguratorV3(_creditConfigurator(creditManager)).rampLiquidationThreshold(
            token, ltFinal, rampStart, rampDuration
        );
    }

    function setFees(
        address creditManager,
        uint16 feeLiquidation,
        uint16 liquidationPremium,
        uint16 feeLiquidationExpired,
        uint16 liquidationPremiumExpired
    ) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        (
            ,
            uint16 feeLiquidationPrev,
            uint16 liquidationDiscountPrev,
            uint16 feeLiquidationExpiredPrev,
            uint16 liquidationDiscountExpiredPrev
        ) = ICreditManagerV3(creditManager).fees();

        if (feeLiquidation + liquidationPremium != feeLiquidationPrev + PERCENTAGE_FACTOR - liquidationDiscountPrev) {
            revert IncorrectParameterException();
        }

        if (
            feeLiquidationExpired + liquidationPremiumExpired
                != feeLiquidationExpiredPrev + PERCENTAGE_FACTOR - liquidationDiscountExpiredPrev
        ) {
            uint256 expirationDate = ICreditFacadeV3(ICreditManagerV3(creditManager).creditFacade()).expirationDate();
            if (expirationDate != 0 && expirationDate < block.timestamp + 14 days) {
                revert ExpirationDateTooSoonException();
            }
        }

        _setFees(
            _creditConfigurator(creditManager),
            feeLiquidation,
            liquidationPremium,
            feeLiquidationExpired,
            liquidationPremiumExpired
        );
    }

    function setExpirationDate(address creditManager, uint40 expirationDate) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);
        if (expirationDate < block.timestamp + 14 days) revert ExpirationDateTooSoonException();

        ICreditConfiguratorV3(_creditConfigurator(creditManager)).setExpirationDate(expirationDate);
    }

    function forbidToken(address creditManager, address token) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        ICreditConfiguratorV3(_creditConfigurator(creditManager)).forbidToken(token);
    }

    function allowToken(address creditManager, address token) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        ICreditConfiguratorV3(_creditConfigurator(creditManager)).allowToken(token);
    }

    function _deployCreditConfigurator(address creditManager, bytes memory params) internal returns (address) {
        return _contractsFactory().deployCreditConfigurator(creditManager, params);
    }

    function _deployCreditFacade(address creditManager, bytes memory params) internal returns (address) {
        return _contractsFactory().deployCreditFacade(creditManager, params);
    }

    function _setCreditFacade(address creditConfigurator, address newCreditFacade, bool migrateParams) internal {
        ICreditConfiguratorV3(creditConfigurator).setCreditFacade(newCreditFacade, migrateParams);
    }

    function _setCreditManagerDebtLimit(address pool, address creditManager, uint256 newLimit) internal {
        IPoolV3(pool).setCreditManagerDebtLimit(creditManager, newLimit);
    }

    function _setFees(
        address creditConfigurator,
        uint16 feeLiquidation,
        uint16 liquidationPremium,
        uint16 feeLiquidationExpired,
        uint16 liquidationPremiumExpired
    ) internal {
        if (
            feeLiquidation > liquidationPremium || feeLiquidationExpired > liquidationPremiumExpired
                || feeLiquidationExpired > feeLiquidation || liquidationPremiumExpired > liquidationPremium
                || liquidationPremium == 0 || liquidationPremiumExpired == 0
        ) {
            revert IncorrectParameterException();
        }
        ICreditConfiguratorV3(creditConfigurator).setFees(
            feeLiquidation, liquidationPremium, feeLiquidationExpired, liquidationPremiumExpired
        );
    }

    // ----------------------- //
    // PRICE ORACLE MANAGEMENT //
    // ----------------------- //

    function setPriceOracle(address pool, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address priceOracle = _deployPriceOracle(acl, params);
        address currentPriceOracle = priceOracles[pool];
        priceOracles[pool] = priceOracle;

        address[] memory tokens = IPriceOracleV3(currentPriceOracle).getTokens();
        uint256 numTokens = tokens.length;
        for (uint256 i; i < numTokens; ++i) {
            PriceFeedParams memory main = IPriceOracleV3(currentPriceOracle).priceFeedParams(tokens[i]);
            _setPriceFeed(priceOracle, tokens[i], main.priceFeed, main.stalenessPeriod, false);

            PriceFeedParams memory reserve = IPriceOracleV3(currentPriceOracle).reservePriceFeedParams(tokens[i]);
            if (reserve.priceFeed != address(0)) {
                _setPriceFeed(priceOracle, tokens[i], reserve.priceFeed, reserve.stalenessPeriod, true);
            }
        }

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            ICreditConfiguratorV3(_creditConfigurator(creditManagers[i])).setPriceOracle(priceOracle);
        }

        address controller_ = controller;
        if (controller_ != address(0)) _setController(priceOracle, controller_);
    }

    function setPriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        address priceOracle = priceOracles[pool];
        if (IPriceOracleV3(priceOracle).priceFeeds(token) == address(0)) revert PriceFeedDoesNotExistException();

        uint32 stalenessPeriod = _ensureAllowedPriceFeed(token, priceFeed);
        if (_getPrice(priceFeed) == 0 && (token == IPoolV3(pool).asset() || _quota(pool, token) != 0)) {
            revert IncorrectPriceException();
        }

        _setPriceFeed(priceOracle, token, priceFeed, stalenessPeriod, false);
    }

    function setReservePriceFeed(address pool, address token, address priceFeed) external onlyOwner {
        _ensureRegisteredPool(pool);

        address priceOracle = priceOracles[pool];

        uint32 stalenessPeriod = _ensureAllowedPriceFeed(token, priceFeed);
        _setPriceFeed(priceOracle, token, priceFeed, stalenessPeriod, true);
    }

    function _deployPriceOracle(address acl, bytes memory params) internal returns (address) {
        return _contractsFactory().deployPriceOracle(acl, params);
    }

    function _setPriceFeed(address priceOracle, address token, address priceFeed, uint32 stalenessPeriod, bool reserve)
        internal
    {
        if (reserve) {
            IPriceOracleV3(priceOracle).setReservePriceFeed(token, priceFeed, stalenessPeriod);
        } else {
            IPriceOracleV3(priceOracle).setPriceFeed(token, priceFeed, stalenessPeriod);
        }
        _addUpdatableFeeds(priceOracle, priceFeed);
    }

    function _ensureAllowedPriceFeed(address token, address priceFeed) internal view returns (uint32) {
        IPriceFeedStore priceFeedStore = _priceFeedStore();
        if (!priceFeedStore.isAllowedPriceFeed(token, priceFeed)) {
            revert PriceFeedNotAllowedException(token, priceFeed);
        }
        return priceFeedStore.getStalenessPeriod(priceFeed);
    }

    function _getPrice(address priceFeed) internal view returns (uint256) {
        (, int256 answer,,,) = IPriceFeed(priceFeed).latestRoundData();
        if (answer < 0) revert IncorrectPriceException();
        return uint256(answer);
    }

    function _addUpdatableFeeds(address priceOracle, address priceFeed) internal {
        try IUpdatablePriceFeed(priceFeed).updatable() returns (bool updatable) {
            if (updatable) IPriceOracleV3(priceOracle).addUpdatablePriceFeed(priceFeed);
        } catch {}
        address[] memory underlyingFeeds = IPriceFeed(priceFeed).getUnderlyingFeeds();
        uint256 numFeeds = underlyingFeeds.length;
        for (uint256 i; i < numFeeds; ++i) {
            _addUpdatableFeeds(priceOracle, underlyingFeeds[i]);
        }
    }

    // ---------------------- //
    // RATE KEEPER MANAGEMENT //
    // ---------------------- //

    function setRateKeeper(address pool, bytes32 type_, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address quotaKeeper = _quotaKeeper(pool);
        address currentRateKeeper = _rateKeeper(quotaKeeper);
        _uninstallRateKeeper(currentRateKeeper);

        address rateKeeper = _deployRateKeeper(pool, type_, params);
        address[] memory tokens = IPoolQuotaKeeperV3(quotaKeeper).quotedTokens();
        uint256 numTokens = tokens.length;
        for (uint256 i; i < numTokens; ++i) {
            _addToken(rateKeeper, tokens[i], type_);
        }
        _installRateKeeper(quotaKeeper, rateKeeper);

        address controller_ = controller;
        if (controller_ != address(0)) _setController(rateKeeper, controller_);
    }

    function configureRateKeeper(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);

        address rateKeeper = _rateKeeper(_quotaKeeper(pool));

        bytes4 selector = bytes4(data);
        if (selector == IControlledTrait.setController.selector || selector == _getAddTokenSelector(rateKeeper)) {
            revert ForbiddenConfigurationCallException(rateKeeper, selector);
        }
        rateKeeper.functionCall(data);
    }

    function _deployRateKeeper(address pool, bytes32 type_, bytes memory params) internal returns (address) {
        return _contractsFactory().deployRateKeeper(pool, type_, params);
    }

    function _addToken(address rateKeeper, address token, bytes32 type_) internal {
        if (type_ == "RK_GAUGE") {
            IGaugeV3(rateKeeper).addQuotaToken({token: token, minRate: 1, maxRate: 1});
        } else if (type_ == "RK_TUMBLER") {
            ITumblerV3(rateKeeper).addToken({token: token, rate: 1});
        } else {
            IRateKeeperExt(rateKeeper).addToken(token);
        }
    }

    function _getAddTokenSelector(address rateKeeper) internal view returns (bytes4) {
        bytes32 type_ = _getRateKeeperType(rateKeeper);
        if (type_ == "RK_GAUGE") return IGaugeV3.addQuotaToken.selector;
        if (type_ == "RK_TUMBLER") return ITumblerV3.addToken.selector;
        return IRateKeeperExt.addToken.selector;
    }

    function _getRateKeeperType(address rateKeeper) internal view returns (bytes32) {
        try IRateKeeperExt(rateKeeper).contractType() returns (bytes32 type_) {
            return type_;
        } catch {
            return "RK_GAUGE";
        }
    }

    function _installRateKeeper(address quotaKeeper, address rateKeeper) internal {
        IPoolQuotaKeeperV3(quotaKeeper).setGauge(rateKeeper);
        if (_isVotingContract(rateKeeper)) {
            _setVotingContractStatus(rateKeeper, VotingContractStatus.ALLOWED);
            try IVotingContractExt(rateKeeper).onInstallCallback() {} catch {}
        }
    }

    function _uninstallRateKeeper(address rateKeeper) internal {
        if (_isVotingContract(rateKeeper)) {
            _setVotingContractStatus(rateKeeper, VotingContractStatus.UNVOTE_ONLY);
            try IVotingContractExt(rateKeeper).onUninstallCallback() {}
            catch {
                IGaugeV3(rateKeeper).setFrozenEpoch(true);
            }
        }
    }

    function _isVotingContract(address rateKeeper) internal view returns (bool) {
        try IVotingContractExt(rateKeeper).voter() returns (address) {
            return true;
        } catch {
            return false;
        }
    }

    function _setVotingContractStatus(address votingContract, VotingContractStatus status) internal {
        IConfiguratorFactory(configuratorFactory).setVotingContractStatus(votingContract, status);
    }

    // -------------- //
    // IRM MANAGEMENT //
    // -------------- //

    function setInterestRateModel(address pool, bytes32 type_, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address irm = _deployInterestRateModel(type_, params);
        IPoolV3(pool).setInterestRateModel(irm);

        address controller_ = controller;
        if (controller_ != address(0)) _setController(irm, controller_);
    }

    function configureInterestRateModel(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);

        address irm = _interestRateModel(pool);

        bytes4 selector = bytes4(data);
        if (selector == IControlledTrait.setController.selector) {
            revert ForbiddenConfigurationCallException(irm, selector);
        }
        irm.functionCall(data);
    }

    function _deployInterestRateModel(bytes32 type_, bytes memory params) internal returns (address) {
        return _contractsFactory().deployInterestRateModel(type_, params);
    }

    // ------------------ //
    // ADAPTER MANAGEMENT //
    // ------------------ //

    function allowAdapter(address creditManager, address targetContract, bytes calldata params) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address adapter = _contractsFactory().deployAdapter(creditManager, targetContract, params);
        ICreditConfiguratorV3(_creditConfigurator(creditManager)).allowAdapter(adapter);
    }

    function forbidAdapter(address creditManager, address targetContract) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address adapter = _getAdapterOrRevert(creditManager, targetContract);
        ICreditConfiguratorV3(_creditConfigurator(creditManager)).forbidAdapter(adapter);
    }

    function configureAdapter(address creditManager, address targetContract, bytes calldata data) external onlyOwner {
        _ensureRegisteredCreditManager(creditManager);

        address adapter = _getAdapterOrRevert(creditManager, targetContract);
        adapter.functionCall(data);
    }

    function _getAdapterOrRevert(address creditManager, address targetContract) internal view returns (address) {
        address adapter = ICreditManagerV3(creditManager).contractToAdapter(targetContract);
        if (adapter == address(0)) revert AdapterNotInitializedException(creditManager, targetContract);
    }

    // ---------------- //
    // ROLES MANAGEMENT //
    // ---------------- //

    function addPausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).addPausableAdmin(admin);
    }

    function addUnpausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).addUnpausableAdmin(admin);
    }

    function removePausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).removePausableAdmin(admin);
    }

    function removeUnpausableAdmin(address admin) external onlyOwner {
        IACLExt(acl).removeUnpausableAdmin(admin);
    }

    function addEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.add(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            _addEmergencyLiquidator(_creditConfigurator(creditManagers[i]), liquidator);
        }
    }

    function removeEmergencyLiquidator(address liquidator) external onlyOwner {
        if (!_emergencyLiquidators.remove(liquidator)) return;
        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            ICreditConfiguratorV3(_creditConfigurator(creditManagers[i])).removeEmergencyLiquidator(liquidator);
        }
    }

    function setLossLiquidator(address pool, bytes32 type_, bytes calldata params) external onlyOwner {
        _ensureRegisteredPool(pool);

        address lossLiquidator = _contractsFactory().deployLossLiquidator(pool, type_, params);

        address[] memory creditManagers = _creditManagers(pool);
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            _setLossLiquidator(_creditConfigurator(creditManagers[i]), lossLiquidator);
        }

        lossLiquidators[pool] = lossLiquidator;

        address controller_ = controller;
        if (controller_ != address(0)) _setController(lossLiquidator, controller_);
    }

    function configureLossLiquidator(address pool, bytes calldata data) external onlyOwner {
        _ensureRegisteredPool(pool);

        address lossLiquidator = lossLiquidators[pool];
        if (lossLiquidator == address(0)) revert LossLiquidatorNotInitializedException(pool);

        bytes4 selector = bytes4(data);
        if (selector == IControlledTrait.setController.selector) {
            revert ForbiddenConfigurationCallException(lossLiquidator, selector);
        }
        lossLiquidator.functionCall(data);
    }

    function setController(bytes calldata params) external onlyOwner {
        address controller_ = _contractsFactory().deployController(acl, params);

        address[] memory pools = _pools();
        uint256 numPools = pools.length;
        for (uint256 i; i < numPools; ++i) {
            address pool = pools[i];
            address quotaKeeper = _quotaKeeper(pool);

            _setController(_interestRateModel(pool), controller_);
            _setController(pool, controller_);
            _setController(quotaKeeper, controller_);
            _setController(_rateKeeper(quotaKeeper), controller_);
            _setController(priceOracles[pool], controller_);

            address lossLiquidator = lossLiquidators[pool];
            if (lossLiquidator != address(0)) _setController(lossLiquidator, controller_);
        }

        address[] memory creditManagers = _creditManagers();
        uint256 numManagers = creditManagers.length;
        for (uint256 i; i < numManagers; ++i) {
            _setController(_creditConfigurator(creditManagers[i]), controller_);
        }

        controller = controller_;
    }

    function configureController(bytes calldata data) external onlyOwner {
        address controller_ = controller;
        if (controller_ == address(0)) revert ControllerNotInitializedException();

        controller_.functionCall(data);
    }

    function _addEmergencyLiquidator(address creditConfigurator, address liquidator) internal {
        ICreditConfiguratorV3(creditConfigurator).addEmergencyLiquidator(liquidator);
    }

    function _setLossLiquidator(address creditConfigurator, address lossLiquidator) internal {
        ICreditConfiguratorV3(creditConfigurator).setLossLiquidator(lossLiquidator);
    }

    function _setController(address contract_, address controller_) internal {
        try IControlledTrait(contract_).setController(controller_) {} catch {}
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _contractsFactory() internal view returns (IContractsFactory) {
        return IContractsFactory(_getLatestContract(AP_CONTRACTS_FACTORY));
    }

    function _priceFeedStore() internal view returns (IPriceFeedStore) {
        return IPriceFeedStore(_getLatestContract(AP_PRICE_FEED_STORE));
    }

    function _getLatestContract(bytes32 type_) internal view returns (address) {
        return IAddressProvider(addressProvider).getLatestAddressOrRevert(type_);
    }

    function _ensureRegisteredPool(address pool) internal view {
        if (!IContractsRegisterExt(contractsRegister).isPool(pool)) {
            revert RegisteredPoolOnlyException();
        }
    }

    function _ensureRegisteredCreditManager(address creditManager) internal view {
        if (!IContractsRegisterExt(contractsRegister).isCreditManager(creditManager)) {
            revert RegisteredCreditManagerOnlyException();
        }
    }

    function _pools() internal view returns (address[] memory) {
        return IContractsRegisterExt(contractsRegister).getPools();
    }

    function _creditManagers() internal view returns (address[] memory) {
        return IContractsRegisterExt(contractsRegister).getCreditManagers();
    }

    function _creditManagers(address pool) internal view returns (address[] memory creditManagers) {
        address[] memory allCreditManagers = _creditManagers();
        uint256 totalManagers = allCreditManagers.length;
        creditManagers = new address[](totalManagers);
        uint256 numManagers;
        for (uint256 i; i < totalManagers; ++i) {
            if (_pool(allCreditManagers[i]) == pool) {
                creditManagers[numManagers++] = allCreditManagers[i];
            }
        }
        assembly {
            mstore(creditManagers, numManagers)
        }
    }

    function _interestRateModel(address pool) internal view returns (address) {
        return IPoolV3(pool).interestRateModel();
    }

    function _quotaKeeper(address pool) internal view returns (address) {
        return IPoolV3(pool).poolQuotaKeeper();
    }

    function _rateKeeper(address quotaKeeper) internal view returns (address) {
        return IPoolQuotaKeeperV3(quotaKeeper).gauge();
    }

    function _quota(address pool, address token) internal view returns (uint96 quota) {
        (,,, quota,,) = IPoolQuotaKeeperV3(_quotaKeeper(pool)).getTokenQuotaParams(token);
    }

    function _pool(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).pool();
    }

    function _creditConfigurator(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).creditConfigurator();
    }
}
