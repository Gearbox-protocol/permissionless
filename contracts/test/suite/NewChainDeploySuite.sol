// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {CrossChainMultisig, CrossChainCall} from "../../global/CrossChainMultisig.sol";
import {InstanceManager} from "../../instance/InstanceManager.sol";
import {PriceFeedStore} from "../../instance/PriceFeedStore.sol";
import {IBytecodeRepository} from "../../interfaces/IBytecodeRepository.sol";
import {IAddressProvider} from "../../interfaces/IAddressProvider.sol";
import {IInstanceManager} from "../../interfaces/IInstanceManager.sol";

import {IWETH} from "@gearbox-protocol/core-v3/contracts/interfaces/external/IWETH.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {
    AP_PRICE_FEED_STORE,
    AP_INTEREST_RATE_MODEL_FACTORY,
    AP_CREDIT_FACTORY,
    AP_POOL_FACTORY,
    AP_PRICE_ORACLE_FACTORY,
    AP_RATE_KEEPER_FACTORY,
    AP_MARKET_CONFIGURATOR_FACTORY,
    AP_LOSS_POLICY_FACTORY,
    AP_GOVERNOR,
    AP_POOL,
    AP_POOL_QUOTA_KEEPER,
    AP_PRICE_ORACLE,
    AP_MARKET_CONFIGURATOR,
    AP_ACL,
    AP_CONTRACTS_REGISTER,
    AP_INTEREST_RATE_MODEL_LINEAR,
    AP_RATE_KEEPER_TUMBLER,
    AP_RATE_KEEPER_GAUGE,
    AP_LOSS_POLICY_DEFAULT,
    AP_CREDIT_MANAGER,
    AP_CREDIT_FACADE,
    AP_CREDIT_CONFIGURATOR
} from "../../libraries/ContractLiterals.sol";
import {SignedProposal, Bytecode} from "../../interfaces/Types.sol";

import {CreditFactory} from "../../factories/CreditFactory.sol";
import {InterestRateModelFactory} from "../../factories/InterestRateModelFactory.sol";
import {LossPolicyFactory} from "../../factories/LossPolicyFactory.sol";
import {PoolFactory} from "../../factories/PoolFactory.sol";
import {PriceOracleFactory} from "../../factories/PriceOracleFactory.sol";
import {RateKeeperFactory} from "../../factories/RateKeeperFactory.sol";

import {MarketConfigurator} from "../../market/MarketConfigurator.sol";
import {MarketConfiguratorFactory} from "../../instance/MarketConfiguratorFactory.sol";
import {ACL} from "../../market/ACL.sol";
import {ContractsRegister} from "../../market/ContractsRegister.sol";
import {Governor} from "../../market/Governor.sol";

import {PoolV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolV3.sol";
import {PoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolQuotaKeeperV3.sol";
import {PriceOracleV3} from "@gearbox-protocol/core-v3/contracts/core/PriceOracleV3.sol";
import {LinearInterestRateModelV3} from "@gearbox-protocol/core-v3/contracts/pool/LinearInterestRateModelV3.sol";
import {TumblerV3} from "@gearbox-protocol/core-v3/contracts/pool/TumblerV3.sol";
import {GaugeV3} from "@gearbox-protocol/core-v3/contracts/pool/GaugeV3.sol";
import {DefaultLossPolicy} from "../../helpers/DefaultLossPolicy.sol";
import {CreditManagerV3} from "@gearbox-protocol/core-v3/contracts/credit/CreditManagerV3.sol";
import {CreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/credit/CreditFacadeV3.sol";
import {CreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/credit/CreditConfiguratorV3.sol";

import {DeployParams} from "../../interfaces/Types.sol";
import {InstanceManagerHelper} from "../../test/helpers/InstanceManagerHelper.sol";
import {CreditFacadeParams, CreditManagerParams} from "../../factories/CreditFactory.sol";

struct SystemContract {
    bytes initCode;
    bytes32 contractType;
    uint256 version;
}

struct DeploySystemContractCall {
    bytes32 contractType;
    uint256 version;
}

contract NewChainDeploySuite is Test, InstanceManagerHelper {
    address internal riskCurator;

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant GEAR = 0xBa3335588D9403515223F109EdC4eB7269a9Ab5D;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant CHAINLINK_ETH_USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    address constant CHAINLINK_USDC_USD = 0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6;

    function setUp() public {
        // simulate chainId 1
        if (block.chainid != 1) {
            vm.chainId(1);
        }

        _setUpInstanceManager();

        _setupInitialSystemContracts();

        // Configure instance
        _setupPriceFeedStore();
        riskCurator = vm.addr(_generatePrivateKey("RISK_CURATOR"));
    }

    function _setupInitialSystemContracts() internal {
        CrossChainCall[] memory calls = new CrossChainCall[](1);
        calls[0] = _generateAddAuditorCall(auditor, "Initial Auditor");
        _submitProposalAndSign(calls);

        SystemContract[22] memory systemContracts = [
            SystemContract({initCode: type(PoolFactory).creationCode, contractType: AP_POOL_FACTORY, version: 3_10}),
            SystemContract({initCode: type(CreditFactory).creationCode, contractType: AP_CREDIT_FACTORY, version: 3_10}),
            SystemContract({
                initCode: type(InterestRateModelFactory).creationCode,
                contractType: AP_INTEREST_RATE_MODEL_FACTORY,
                version: 3_10
            }),
            SystemContract({initCode: type(PriceFeedStore).creationCode, contractType: AP_PRICE_FEED_STORE, version: 3_10}),
            SystemContract({
                initCode: type(PriceOracleFactory).creationCode,
                contractType: AP_PRICE_ORACLE_FACTORY,
                version: 3_10
            }),
            SystemContract({
                initCode: type(RateKeeperFactory).creationCode,
                contractType: AP_RATE_KEEPER_FACTORY,
                version: 3_10
            }),
            SystemContract({
                initCode: type(MarketConfiguratorFactory).creationCode,
                contractType: AP_MARKET_CONFIGURATOR_FACTORY,
                version: 3_10
            }),
            SystemContract({initCode: type(Governor).creationCode, contractType: AP_GOVERNOR, version: 3_10}),
            SystemContract({initCode: type(PoolV3).creationCode, contractType: AP_POOL, version: 3_10}),
            SystemContract({
                initCode: type(PoolQuotaKeeperV3).creationCode,
                contractType: AP_POOL_QUOTA_KEEPER,
                version: 3_10
            }),
            SystemContract({
                initCode: type(LinearInterestRateModelV3).creationCode,
                contractType: AP_INTEREST_RATE_MODEL_LINEAR,
                version: 3_10
            }),
            SystemContract({initCode: type(TumblerV3).creationCode, contractType: AP_RATE_KEEPER_TUMBLER, version: 3_10}),
            SystemContract({initCode: type(GaugeV3).creationCode, contractType: AP_RATE_KEEPER_GAUGE, version: 3_10}),
            SystemContract({initCode: type(PriceOracleV3).creationCode, contractType: AP_PRICE_ORACLE, version: 3_10}),
            SystemContract({
                initCode: type(DefaultLossPolicy).creationCode,
                contractType: AP_LOSS_POLICY_DEFAULT,
                version: 3_10
            }),
            SystemContract({
                initCode: type(MarketConfigurator).creationCode,
                contractType: AP_MARKET_CONFIGURATOR,
                version: 3_10
            }),
            SystemContract({initCode: type(ACL).creationCode, contractType: AP_ACL, version: 3_10}),
            SystemContract({
                initCode: type(ContractsRegister).creationCode,
                contractType: AP_CONTRACTS_REGISTER,
                version: 3_10
            }),
            SystemContract({
                initCode: type(LossPolicyFactory).creationCode,
                contractType: AP_LOSS_POLICY_FACTORY,
                version: 3_10
            }),
            /// CREDIT
            SystemContract({initCode: type(CreditManagerV3).creationCode, contractType: AP_CREDIT_MANAGER, version: 3_10}),
            SystemContract({initCode: type(CreditFacadeV3).creationCode, contractType: AP_CREDIT_FACADE, version: 3_10}),
            SystemContract({
                initCode: type(CreditConfiguratorV3).creationCode,
                contractType: AP_CREDIT_CONFIGURATOR,
                version: 3_10
            })
        ];

        uint256 len = systemContracts.length;

        DeploySystemContractCall[8] memory deployCalls = [
            DeploySystemContractCall({contractType: AP_PRICE_FEED_STORE, version: 3_10}),
            DeploySystemContractCall({contractType: AP_POOL_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_CREDIT_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_PRICE_ORACLE_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_INTEREST_RATE_MODEL_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_RATE_KEEPER_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_LOSS_POLICY_FACTORY, version: 3_10}),
            DeploySystemContractCall({contractType: AP_MARKET_CONFIGURATOR_FACTORY, version: 3_10})
        ];

        uint256 deployCallsLen = deployCalls.length;

        calls = new CrossChainCall[](len + deployCallsLen + 1);
        for (uint256 i = 0; i < len; i++) {
            bytes32 bytecodeHash = _uploadByteCodeAndSign(
                systemContracts[i].initCode, systemContracts[i].contractType, systemContracts[i].version
            );
            calls[i] = _generateAllowSystemContractCall(bytecodeHash);
        }

        for (uint256 i = 0; i < deployCallsLen; i++) {
            calls[len + i] = _generateDeploySystemContractCall(deployCalls[i].contractType, deployCalls[i].version);
        }

        calls[len + deployCallsLen] = _generateActivateCall(instanceOwner, address(0), WETH, GEAR);

        _submitProposalAndSign(calls);
    }

    function _setupPriceFeedStore() internal {
        _addPriceFeed(CHAINLINK_ETH_USD, 1 days);
        _addPriceFeed(CHAINLINK_USDC_USD, 1 days);

        _allowPriceFeed(WETH, CHAINLINK_ETH_USD);
        _allowPriceFeed(USDC, CHAINLINK_USDC_USD);
    }

    function test_NCD_01_createMarket() public {
        address ap = instanceManager.addressProvider();

        address mcf = IAddressProvider(ap).getAddressOrRevert(AP_MARKET_CONFIGURATOR_FACTORY, 3_10);

        address poolFactory = IAddressProvider(ap).getAddressOrRevert(AP_POOL_FACTORY, 3_10);

        IWETH(WETH).deposit{value: 1e18}();
        IERC20(WETH).transfer(poolFactory, 1e18);

        vm.startPrank(riskCurator);
        address mc = MarketConfiguratorFactory(mcf).createMarketConfigurator(
            riskCurator, riskCurator, "Test Risk Curator", false
        );

        string memory name = "Test Market ETH";
        string memory symbol = "dETH";

        address pool = MarketConfigurator(mc).previewPoolAddress(3_10, WETH, name, symbol);

        bytes memory interestRateModelParams =
            abi.encode(uint16(100), uint16(200), uint16(100), uint16(100), uint16(200), uint16(300), false);
        bytes memory rateKeeperParams = abi.encode(pool, 7 days);
        bytes memory lossPolicyParams = abi.encode(pool, ap);

        address poolFromMarket = MarketConfigurator(mc).createMarket({
            minorVersion: 3_10,
            underlying: WETH,
            name: name,
            symbol: symbol,
            interestRateModelParams: DeployParams("LINEAR", interestRateModelParams),
            rateKeeperParams: DeployParams("TUMBLER", rateKeeperParams),
            lossPolicyParams: DeployParams("DEFAULT", lossPolicyParams),
            underlyingPriceFeed: CHAINLINK_ETH_USD
        });

        assertEq(pool, poolFromMarket);

        address mainnetAF = 0x444CD42BaEdDEB707eeD823f7177b9ABcC779C04;
        address botList = 0x6B24183313074ABb6E3B30Ea206F20c12205053a;

        CreditManagerParams memory creditManagerParams = CreditManagerParams({
            accountFactory: mainnetAF,
            maxEnabledTokens: 4,
            feeInterest: 10_00,
            feeLiquidation: 1_50,
            liquidationPremium: 1_50,
            feeLiquidationExpired: 1_50,
            liquidationPremiumExpired: 1_50,
            minDebt: 1e18,
            maxDebt: 20e18,
            name: "Credit Manager ETH"
        });

        CreditFacadeParams memory facadeParams =
            CreditFacadeParams({botList: botList, degenNFT: address(0), expirable: false});

        bytes memory creditSuiteParams = abi.encode(creditManagerParams, facadeParams);

        MarketConfigurator(mc).createCreditSuite(3_10, pool, creditSuiteParams);

        vm.stopPrank();
    }
}
