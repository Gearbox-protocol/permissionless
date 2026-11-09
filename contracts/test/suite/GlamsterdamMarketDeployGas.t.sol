// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {CrossChainCall} from "../../global/CrossChainMultisig.sol";
import {IAddressProvider} from "../../interfaces/IAddressProvider.sol";
import {DeployParams} from "../../interfaces/Types.sol";
import {CreditFacadeParams, CreditManagerParams} from "../../factories/CreditFactory.sol";
import {MarketConfigurator} from "../../market/MarketConfigurator.sol";
import {MarketConfiguratorFactory} from "../../instance/MarketConfiguratorFactory.sol";

import {ERC20Mock} from "@gearbox-protocol/core-v3/contracts/test/mocks/token/ERC20Mock.sol";

import {AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL} from "../../libraries/ContractLiterals.sol";

import {GlobalSetup} from "../helpers/GlobalSetup.sol";
import {MockPriceFeed} from "../mocks/MockPriceFeed.sol";
import {TestKeys} from "../helpers/TestKeys.sol";

import {VmSafe} from "forge-std/Vm.sol";

/// @dev Foundry's Gas struct gained `gasStateUsed` for EIP-8037; forge-std in this repo is still on the old layout.
struct GasAmsterdam {
    uint64 gasLimit;
    uint64 gasTotalUsed;
    uint64 gasMemoryUsed;
    int64 gasRefunded;
    uint64 gasRemaining;
    uint64 gasStateUsed;
}

interface VmAmsterdamGas {
    function lastCallGas() external view returns (GasAmsterdam memory gas);
}

/// @notice Measures standard permissionless market deployment gas under Amsterdam rules
///         on a Glamsterdam Sepolia fork (~200M block gas limit).
///
/// Run (set `GLAMSTERDAM_FORK_RPC` to a Glamsterdam Sepolia RPC, e.g. in `.env`):
///   forge test --match-path contracts/test/suite/GlamsterdamMarketDeployGas.t.sol \
///     --evm-version amsterdam --hardfork amsterdam -vvv --isolate
///
/// Note: `--evm-version amsterdam` sets the Solidity target; `--hardfork amsterdam`
/// enables EIP-8037/8038 runtime gas metering in Foundry. Under EIP-8037, CREATE/code
/// deposit costs are state gas (`gasStateUsed`), not regular execution gas.
contract GlamsterdamMarketDeployGasTest is Test, GlobalSetup {
    VmAmsterdamGas internal constant vmA = VmAmsterdamGas(address(uint160(uint256(keccak256("hevm cheat code")))));

    string constant NAME = "Test Market ETH";
    string constant SYMBOL = "dETH";

    address internal riskCurator;
    address internal instanceOwner;
    address internal addressProvider;
    address internal weth;
    address internal gear;
    address internal ethUsdFeed;

    VmSafe.Wallet internal bytecodeAuthor;
    VmSafe.Wallet internal auditor;

    uint256 internal blockGasLimit;

    function setUp() public {
        vm.createSelectFork(vm.envString("GLAMSTERDAM_FORK_RPC"));
        blockGasLimit = block.gaslimit;

        // CCG `signBatch` is mainnet-only; EIP-712 domains are hardcoded to chainId 1.
        vm.chainId(1);

        TestKeys testKeys = new TestKeys();
        bytecodeAuthor = testKeys.bytecodeAuthor();
        auditor = testKeys.auditor();
        instanceOwner = testKeys.instanceOwner().addr;
        riskCurator = makeAddr("RISK_CURATOR");

        _deployGlobalContracts(
            testKeys.initialSigners(),
            bytecodeAuthor,
            auditor,
            "Initial Auditor",
            testKeys.threshold(),
            testKeys.dao().addr
        );

        weth = address(new ERC20Mock("Mock WETH", "WETH", 18));
        gear = address(new ERC20Mock("Mock GEAR", "GEAR", 18));
        ethUsdFeed = address(new MockPriceFeed());
        MockPriceFeed(ethUsdFeed).setPrice(2000e8);
        ERC20Mock(weth).mint(address(this), 1_000_000 ether);

        CrossChainCall[] memory calls = new CrossChainCall[](1);
        calls[0] = _generateActivateCall(1, instanceOwner, makeAddr("TREASURY"), weth, gear);
        _submitBatchAndSign("Activate instance", calls);

        addressProvider = instanceManager.addressProvider();
        _addPriceFeed(instanceOwner, ethUsdFeed, 1 days, "ETH/USD");
        _allowPriceFeed(instanceOwner, weth, ethUsdFeed);
    }

    function _isTestMode() internal pure override returns (bool) {
        return true;
    }

    struct StepGas {
        uint256 execGas;
        uint256 stateGas;
        uint256 billable;
    }

    function _readLastCallGas() internal view returns (StepGas memory step) {
        GasAmsterdam memory g = vmA.lastCallGas();
        step.execGas = uint256(g.gasTotalUsed);
        step.stateGas = uint256(g.gasStateUsed);
        step.billable = step.execGas > step.stateGas ? step.execGas : step.stateGas;
    }

    function _logStep(string memory label, StepGas memory step) internal view {
        console.log(label);
        console.log("  execution gas", step.execGas);
        console.log("  state gas    ", step.stateGas);
        console.log("  billable max ", step.billable);
        assertTrue(step.execGas <= blockGasLimit, "execution gas exceeds block gas limit");
        assertTrue(step.stateGas <= blockGasLimit, "state gas exceeds block gas limit");
    }

    function _createMarketConfigurator() internal returns (address mc, StepGas memory step) {
        address mcf =
            IAddressProvider(addressProvider).getAddressOrRevert(AP_MARKET_CONFIGURATOR_FACTORY, NO_VERSION_CONTROL);
        vm.prank(riskCurator);
        mc = MarketConfiguratorFactory(mcf).createMarketConfigurator({
            emergencyAdmin: riskCurator,
            adminFeeTreasury: address(0),
            curatorName: "Test Risk Curator",
            deployGovernor: false
        });
        step = _readLastCallGas();
    }

    function _createDefaultMarket(address mc) internal returns (address pool, StepGas memory step) {
        ERC20Mock(weth).transfer(mc, 1e5);
        address poolPreview = MarketConfigurator(mc).previewCreateMarket(3_10, weth, NAME, SYMBOL);

        vm.prank(riskCurator);
        pool = MarketConfigurator(mc).createMarket({
            minorVersion: 3_10,
            underlying: weth,
            name: NAME,
            symbol: SYMBOL,
            interestRateModelParams: DeployParams({
                postfix: "LINEAR",
                salt: 0,
                constructorParams: abi.encode(100, 200, 100, 100, 200, 300, false)
            }),
            rateKeeperParams: DeployParams({
                postfix: "TUMBLER", salt: 0, constructorParams: abi.encode(poolPreview, 7 days)
            }),
            lossPolicyParams: DeployParams({
                postfix: "ALIASED", salt: 0, constructorParams: abi.encode(poolPreview, addressProvider)
            }),
            underlyingPriceFeed: ethUsdFeed
        });
        step = _readLastCallGas();
        assertEq(pool, poolPreview);
    }

    function _createDefaultCreditSuite(address mc, address pool) internal returns (StepGas memory step) {
        DeployParams memory accountFactoryParams =
            DeployParams({postfix: "DEFAULT", salt: 0, constructorParams: abi.encode(addressProvider)});
        bytes memory creditSuiteParams = abi.encode(
            CreditManagerParams({
                maxEnabledTokens: 4,
                feeInterest: 10_00,
                feeLiquidation: 1_50,
                liquidationPremium: 1_50,
                feeLiquidationExpired: 1_50,
                liquidationPremiumExpired: 1_50,
                minDebt: 1 ether,
                maxDebt: 20 ether,
                name: "Credit Manager ETH",
                accountFactoryParams: accountFactoryParams
            }),
            CreditFacadeParams({degenNFT: address(0), expirable: false, migrateBotList: false})
        );

        vm.prank(riskCurator);
        address creditManager = MarketConfigurator(mc).createCreditSuite(3_10, pool, creditSuiteParams);
        step = _readLastCallGas();
        assertTrue(creditManager != address(0));
    }

    function test_Glamsterdam_standardMarketDeploy_fitsBlockGasLimit() public {
        console.log("fork block.gaslimit", blockGasLimit);
        // Sepolia targets ~200M via EIP-1559 1/1024 voting; exact value drifts slightly.
        assertGe(blockGasLimit, 190_000_000, "expected Glamsterdam Sepolia ~200M block gas limit");

        (address mc, StepGas memory gMc) = _createMarketConfigurator();
        _logStep("createMarketConfigurator", gMc);

        (address pool, StepGas memory gMarket) = _createDefaultMarket(mc);
        _logStep("createMarket", gMarket);

        StepGas memory gCredit = _createDefaultCreditSuite(mc, pool);
        _logStep("createCreditSuite", gCredit);

        uint256 totalState = gMc.stateGas + gMarket.stateGas + gCredit.stateGas;
        uint256 totalExec = gMc.execGas + gMarket.execGas + gCredit.execGas;
        uint256 totalBillable = gMc.billable + gMarket.billable + gCredit.billable;

        console.log("---- totals (3 separate txs) ----");
        console.log("sum execution gas", totalExec);
        console.log("sum state gas    ", totalState);
        console.log("sum billable max ", totalBillable);
        console.log("block gas limit  ", blockGasLimit);
        console.log(
            "largest step headroom",
            blockGasLimit > gCredit.billable ? blockGasLimit - gCredit.billable : 0
        );

        // Protocol constraint: each deploy is its own transaction. Per-step checks in `_logStep`
        // already assert exec/state <= block.gaslimit. The sequential sum can exceed one block;
        // that only matters if someone tried to batch all three into a single block/tx.
        assertTrue(gMc.billable <= blockGasLimit, "createMarketConfigurator exceeds block");
        assertTrue(gMarket.billable <= blockGasLimit, "createMarket exceeds block");
        assertTrue(gCredit.billable <= blockGasLimit, "createCreditSuite exceeds block");
        if (totalBillable > blockGasLimit) {
            console.log("NOTE: sum of the three steps exceeds one block; keep them as separate txs");
        }
    }
}
