// SPDX-License-Identifier: UNLICENSED
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {Test, stdStorage, StdStorage} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {LibString} from "@solady/utils/LibString.sol";

import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";

import {ConstantPriceFeed} from "../../helpers/ConstantPriceFeed.sol";

import {IMarketConfigurator} from "../../interfaces/IMarketConfigurator.sol";
import {AuditReport, Bytecode, DeployParams} from "../../interfaces/Types.sol";
import {
    ICreditConfigureActions,
    CreditFacadeParams,
    CreditManagerParams
} from "../../interfaces/factories/ICreditConfigureActions.sol";
import {IPoolConfigureActions} from "../../interfaces/factories/IPoolConfigureActions.sol";
import {IPriceOracleConfigureActions} from "../../interfaces/factories/IPriceOracleConfigureActions.sol";

import {Domain} from "../../libraries/Domain.sol";

import {AttachBase} from "./AttachBase.sol";

contract AttachTestBase is AttachBase, Test {
    using LibString for bytes32;
    using stdStorage for StdStorage;

    // ---- //
    // CORE //
    // ---- //

    VmSafe.Wallet public author;
    VmSafe.Wallet public auditor;

    address zeroPriceFeed;
    address onePriceFeed;

    function _attachCore() internal virtual override {
        super._attachCore();

        author = vm.createWallet("MockAuthor");
        auditor = vm.createWallet("MockAuditor");

        _configureGlobal(
            address(bytecodeRepository), abi.encodeCall(bytecodeRepository.addAuditor, (auditor.addr, "MockAuditor"))
        );

        zeroPriceFeed = priceFeedStore.zeroPriceFeed();
        _addPriceFeed(zeroPriceFeed, 0, "$0 price feed");
        if (bytecodeRepository.getAllowedBytecodeHash("PRICE_FEED::CONSTANT", 3_10) == 0) {
            // NOTE: this would fail on deployment if we bump `ConstantPriceFeed` to v3.1.1,
            // but we assume that in this case v3.1.0 is already uploaded to the repository
            _uploadContract("PRICE_FEED::CONSTANT", 3_10, type(ConstantPriceFeed).creationCode);
        }
        onePriceFeed = _deploy("PRICE_FEED::CONSTANT", 3_10, abi.encode(1e8, "$1 price feed"));
        _addPriceFeed(onePriceFeed, 0, "$1 price feed");
    }

    function _addPublicDomain(bytes32 domain) internal {
        if (bytecodeRepository.isPublicDomain(domain)) return;

        _configureGlobal(address(bytecodeRepository), abi.encodeCall(bytecodeRepository.addPublicDomain, (domain)));
    }

    function _uploadContract(bytes32 contractType, uint256 version, bytes memory initCode) internal {
        bytes32 allowedBytecodeHash = bytecodeRepository.getAllowedBytecodeHash(contractType, version);
        if (allowedBytecodeHash != 0) {
            bytes memory uploadedInitCode = bytecodeRepository.getBytecode(allowedBytecodeHash).initCode;
            require(
                keccak256(initCode) == keccak256(uploadedInitCode),
                string.concat("Bytecode mismatch for ", contractType.fromSmallString(), " v", vm.toString(version))
            );
            return;
        }

        Bytecode memory bytecode;
        bytecode.contractType = contractType;
        bytecode.version = version;
        bytecode.initCode = initCode;
        bytecode.source = "https://github.com/Gearbox-protocol/mock-contract-source-url";
        _signBytecode(author, bytecode);

        vm.prank(author.addr);
        bytecodeRepository.uploadBytecode(bytecode);

        bytes32 bytecodeHash = bytecodeRepository.computeBytecodeHash(bytecode);

        AuditReport memory auditReport;
        auditReport.reportUrl = "https://github.com/Gearbox-protocol/mock-audit-report-url";
        _signAuditReport(auditor, bytecodeHash, auditReport);
        bytecodeRepository.submitAuditReport(bytecodeHash, auditReport);

        if (bytecodeRepository.isPublicDomain(Domain.extractDomain(contractType))) {
            if (bytecodeRepository.getContractTypeOwner(contractType) != address(0)) {
                stdstore.target(address(bytecodeRepository)).sig("getContractTypeOwner(bytes32)").with_key(contractType)
                    .checked_write(author.addr);
            }
            bytecodeRepository.allowPublicContract(bytecodeHash);
        } else {
            _configureGlobal(
                address(bytecodeRepository), abi.encodeCall(bytecodeRepository.allowSystemContract, (bytecodeHash))
            );
        }
    }

    function _deploy(bytes32 contractType, uint256 version, bytes memory constructorParams) internal returns (address) {
        return bytecodeRepository.deploy({
            contractType: contractType, version: version, constructorParams: constructorParams, salt: "GEARBOX"
        });
    }

    function _configureGlobal(address target, bytes memory data) internal {
        vm.prank(crossChainGovernance);
        instanceManager.configureGlobal(target, data);
    }

    function _configureLocal(address target, bytes memory data) internal {
        vm.prank(instanceOwner);
        instanceManager.configureLocal(target, data);
    }

    function _addPriceFeed(address priceFeed, uint32 stalenessPeriod, string memory name) internal {
        if (priceFeedStore.isKnownPriceFeed(priceFeed)) return;

        _configureLocal(
            address(priceFeedStore), abi.encodeCall(priceFeedStore.addPriceFeed, (priceFeed, stalenessPeriod, name))
        );
    }

    function _allowPriceFeed(address token, address priceFeed) internal {
        if (priceFeedStore.isAllowedPriceFeed(token, priceFeed)) return;

        _configureLocal(address(priceFeedStore), abi.encodeCall(priceFeedStore.allowPriceFeed, (token, priceFeed)));
    }

    // ------- //
    // MARKETS //
    // ------- //

    IMarketConfigurator public marketConfigurator;
    address public riskCurator;

    function _attachMarketConfigurator() internal {
        address configurator = vm.envOr("MARKET_CONFIGURATOR", address(0));
        if (configurator == address(0)) {
            configurator = _createMockMarketConfigurator();
            console.log("Using mock market configurator");
        } else {
            if (IMarketConfigurator(configurator).contractType() != "MARKET_CONFIGURATOR") {
                revert("MARKET_CONFIGURATOR is not a market configurator");
            }
            if (!bytecodeRepository.isDeployedFromRepository(configurator)) {
                revert("Market configurator is not deployed from repository");
            }
            console.log("Attached to market configurator", configurator);
        }
        marketConfigurator = IMarketConfigurator(configurator);
        riskCurator = marketConfigurator.admin();
    }

    function _createMockMarketConfigurator() internal returns (address configurator) {
        address curator = makeAddr("MockCurator");
        vm.prank(curator);
        configurator = marketConfiguratorFactory.createMarketConfigurator({
            emergencyAdmin: address(0), adminFeeTreasury: address(0), curatorName: "MockCurator", deployGovernor: false
        });
    }

    struct MarketParams {
        string name;
        string symbol;
        DeployParams interestRateModelParams;
        DeployParams rateKeeperParams;
        DeployParams lossPolicyParams;
        address underlyingPriceFeed;
    }

    function _getDefaultMarketParams(address underlying) internal view returns (MarketParams memory) {
        string memory name = string.concat("Mock Diesel ", ERC20(underlying).name());
        string memory symbol = string.concat("md", ERC20(underlying).symbol());
        address pool = marketConfigurator.previewCreateMarket({
            minorVersion: 3_10, underlying: underlying, name: name, symbol: symbol
        });
        return MarketParams({
            name: name,
            symbol: symbol,
            interestRateModelParams: DeployParams({
                postfix: "LINEAR", salt: "GEARBOX", constructorParams: abi.encode(5000, 9000, 10_00, 0, 0, 0, false)
            }),
            rateKeeperParams: DeployParams({
                postfix: "TUMBLER", salt: "GEARBOX", constructorParams: abi.encode(pool, 0)
            }),
            lossPolicyParams: DeployParams({
                postfix: "ALIASED", salt: "GEARBOX", constructorParams: abi.encode(pool, ADDRESS_PROVIDER)
            }),
            underlyingPriceFeed: onePriceFeed
        });
    }

    function _createDefaultMockMarket(address underlying) internal returns (address) {
        return _createMockMarket(underlying, _getDefaultMarketParams(underlying));
    }

    function _createMockMarket(address underlying, MarketParams memory params) internal returns (address pool) {
        vm.prank(riskCurator);
        pool = marketConfigurator.createMarket({
            minorVersion: 3_10,
            underlying: underlying,
            name: params.name,
            symbol: params.symbol,
            interestRateModelParams: params.interestRateModelParams,
            rateKeeperParams: params.rateKeeperParams,
            lossPolicyParams: params.lossPolicyParams,
            underlyingPriceFeed: params.underlyingPriceFeed
        });
    }

    struct CreditSuiteParams {
        uint128 minDebt;
        uint128 maxDebt;
        uint256 debtLimit;
        uint8 maxEnabledTokens;
        uint16 feeInterest;
        uint16 feeLiquidation;
        uint16 liquidationPremium;
        uint16 feeLiquidationExpired;
        uint16 liquidationPremiumExpired;
        address degenNFT;
        bool expirable;
        bool migrateBotList;
        DeployParams accountFactoryParams;
    }

    function _getDefaultCreditSuiteParams() internal pure returns (CreditSuiteParams memory) {
        return CreditSuiteParams({
            minDebt: 0,
            maxDebt: 0,
            debtLimit: 0,
            maxEnabledTokens: 2,
            feeInterest: 50_00,
            feeLiquidation: 1_00,
            liquidationPremium: 1_00,
            feeLiquidationExpired: 1_00,
            liquidationPremiumExpired: 1_00,
            degenNFT: address(0),
            expirable: false,
            migrateBotList: false,
            accountFactoryParams: DeployParams({
                postfix: "DEFAULT", salt: "GEARBOX", constructorParams: abi.encode(ADDRESS_PROVIDER)
            })
        });
    }

    function _createDefaultMockCreditSuite(address pool) internal returns (address) {
        return _createMockCreditSuite(pool, _getDefaultCreditSuiteParams());
    }

    function _createMockCreditSuite(address pool, CreditSuiteParams memory params)
        internal
        returns (address creditManager)
    {
        CreditManagerParams memory cmParams = CreditManagerParams({
            maxEnabledTokens: params.maxEnabledTokens,
            feeInterest: params.feeInterest,
            feeLiquidation: params.feeLiquidation,
            liquidationPremium: params.liquidationPremium,
            feeLiquidationExpired: params.feeLiquidationExpired,
            liquidationPremiumExpired: params.liquidationPremiumExpired,
            minDebt: params.minDebt,
            maxDebt: params.maxDebt,
            name: string.concat("Mock ", ERC20(ERC4626(pool).asset()).symbol(), " Credit Suite"),
            accountFactoryParams: params.accountFactoryParams
        });

        CreditFacadeParams memory cfParams = CreditFacadeParams({
            degenNFT: params.degenNFT, expirable: params.expirable, migrateBotList: params.migrateBotList
        });

        vm.startPrank(riskCurator);
        creditManager = marketConfigurator.createCreditSuite({
            minorVersion: 3_10, pool: pool, encdodedParams: abi.encode(cmParams, cfParams)
        });

        if (params.debtLimit != 0) {
            marketConfigurator.configurePool(
                pool, abi.encodeCall(IPoolConfigureActions.setCreditManagerDebtLimit, (creditManager, params.debtLimit))
            );
        }
        vm.stopPrank();
    }

    struct TokenParams {
        address token;
        address priceFeed;
        address reservePriceFeed;
        uint96 quotaLimit;
        uint16 quotaRate;
    }

    function _getDefaultTokenParams(address token) internal view returns (TokenParams memory) {
        return TokenParams({
            token: token, priceFeed: zeroPriceFeed, reservePriceFeed: address(0), quotaLimit: 0, quotaRate: 0
        });
    }

    function _addDefaultToken(address pool, address token) internal {
        _addToken(pool, _getDefaultTokenParams(token));
    }

    function _addToken(address pool, TokenParams memory params) internal {
        vm.startPrank(riskCurator);

        marketConfigurator.addToken({pool: pool, token: params.token, priceFeed: params.priceFeed});

        if (params.reservePriceFeed != address(0)) {
            marketConfigurator.configurePriceOracle(
                pool,
                abi.encodeCall(
                    IPriceOracleConfigureActions.setReservePriceFeed, (params.token, params.reservePriceFeed)
                )
            );
        }
        if (params.quotaLimit != 0) {
            marketConfigurator.configurePool(
                pool, abi.encodeCall(IPoolConfigureActions.setTokenLimit, (params.token, params.quotaLimit))
            );
        }
        if (params.quotaRate != 0) {
            marketConfigurator.configureRateKeeper(
                pool, abi.encodeCall(ITumblerV3.setRate, (params.token, params.quotaRate))
            );
        }

        vm.stopPrank();
    }

    function _addCollateralToken(address creditManager, address token, uint16 lt) internal {
        vm.prank(riskCurator);
        marketConfigurator.configureCreditSuite(
            creditManager, abi.encodeCall(ICreditConfigureActions.addCollateralToken, (token, lt))
        );
    }

    function _allowAdapter(address creditManager, bytes32 postfix, bytes memory constructorParams) internal {
        vm.prank(riskCurator);
        marketConfigurator.configureCreditSuite(
            creditManager,
            abi.encodeCall(
                ICreditConfigureActions.allowAdapter,
                (DeployParams({postfix: postfix, salt: "GEARBOX", constructorParams: constructorParams}))
            )
        );
    }

    function _configureAdapter(address creditManager, address targetContract, bytes memory data) internal {
        vm.prank(riskCurator);
        marketConfigurator.configureCreditSuite(
            creditManager, abi.encodeCall(ICreditConfigureActions.configureAdapterFor, (targetContract, data))
        );
    }

    function _updateQuotaRates(address pool) internal {
        vm.prank(riskCurator);
        IMarketConfigurator(marketConfigurator).configureRateKeeper(pool, abi.encodeCall(ITumblerV3.updateRates, ()));
    }

    function _addPeripheryContract(address peripheryContract) internal {
        vm.prank(riskCurator);
        IMarketConfigurator(marketConfigurator).addPeripheryContract(peripheryContract);
    }
}
