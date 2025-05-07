// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

// Adapters
import {BalancerV2VaultAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/balancer/BalancerV2VaultAdapter.sol";
import {BalancerV3RouterAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/balancer/BalancerV3RouterAdapter.sol";
import {CamelotV3Adapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/camelot/CamelotV3Adapter.sol";
import {ConvexV1BaseRewardPoolAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/convex/ConvexV1_BaseRewardPool.sol";
import {ConvexV1BoosterAdapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/convex/ConvexV1_Booster.sol";
import {CurveV1Adapter2Assets} from "@gearbox-protocol/integrations-v3/contracts/adapters/curve/CurveV1_2.sol";
import {CurveV1Adapter3Assets} from "@gearbox-protocol/integrations-v3/contracts/adapters/curve/CurveV1_3.sol";
import {CurveV1Adapter4Assets} from "@gearbox-protocol/integrations-v3/contracts/adapters/curve/CurveV1_4.sol";
import {CurveV1AdapterStableNG} from "@gearbox-protocol/integrations-v3/contracts/adapters/curve/CurveV1_StableNG.sol";
import {CurveV1AdapterStETH} from "@gearbox-protocol/integrations-v3/contracts/adapters/curve/CurveV1_stETH.sol";
import {ERC4626Adapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/erc4626/ERC4626Adapter.sol";
import {EqualizerRouterAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/equalizer/EqualizerRouterAdapter.sol";
import {LidoV1Adapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/lido/LidoV1.sol";
import {MellowVaultAdapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/mellow/MellowVaultAdapter.sol";
import {Mellow4626VaultAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/mellow/Mellow4626VaultAdapter.sol";
import {PendleRouterAdapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/pendle/PendleRouterAdapter.sol";
import {DaiUsdsAdapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/sky/DaiUsdsAdapter.sol";
import {StakingRewardsAdapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/sky/StakingRewardsAdapter.sol";
import {UniswapV2Adapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/uniswap/UniswapV2.sol";
import {UniswapV3Adapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/uniswap/UniswapV3.sol";
import {VelodromeV2RouterAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/velodrome/VelodromeV2RouterAdapter.sol";
import {YearnV2Adapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/yearn/YearnV2.sol";
import {ZircuitPoolAdapter} from "@gearbox-protocol/integrations-v3/contracts/adapters/zircuit/ZircuitPoolAdapter.sol";
import {TraderJoeRouterAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/traderjoe/TraderJoeRouterAdapter.sol";
import {InfraredVaultAdapter} from
    "@gearbox-protocol/integrations-v3/contracts/adapters/infrared/InfraredVaultAdapter.sol";

// Price Feeds
import {BoundedPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/BoundedPriceFeed.sol";
import {CompositePriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/CompositePriceFeed.sol";
import {ZeroPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/ZeroPriceFeed.sol";
import {ConstantPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/ConstantPriceFeed.sol";

// Balancer Price Feeds
import {BPTStablePriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/balancer/BPTStablePriceFeed.sol";
import {BPTWeightedPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/balancer/BPTWeightedPriceFeed.sol";

// Curve Price Feeds
import {CurveStableLPPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/curve/CurveStableLPPriceFeed.sol";
import {CurveCryptoLPPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/curve/CurveCryptoLPPriceFeed.sol";
import {CurveTWAPPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/curve/CurveTWAPPriceFeed.sol";

// Lido Price Feeds
import {WstETHPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/lido/WstETHPriceFeed.sol";

// Yearn Price Feeds
import {YearnPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/yearn/YearnPriceFeed.sol";

// ERC4626 Price Feeds
import {ERC4626PriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/erc4626/ERC4626PriceFeed.sol";

// Mellow Price Feeds
import {MellowLRTPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/mellow/MellowLRTPriceFeed.sol";

// Pendle Price Feeds
import {PendleTWAPPTPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/pendle/PendleTWAPPTPriceFeed.sol";

// Updatable Price Feeds
import {PythPriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/updatable/PythPriceFeed.sol";
import {RedstonePriceFeed} from "@gearbox-protocol/oracles-v3/contracts/oracles/updatable/RedstonePriceFeed.sol";

struct BytecodeConfig {
    bytes32 contractType;
    uint256 version;
    bytes initCode;
}

contract BytecodeConfigs {
    BytecodeConfig[] internal _configs;

    constructor() {
        /// Adapters

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::BALANCER_VAULT",
                version: 310,
                initCode: type(BalancerV2VaultAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::BALANCER_V3_ROUTER",
                version: 310,
                initCode: type(BalancerV3RouterAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CVX_V1_BOOSTER",
                version: 310,
                initCode: type(ConvexV1BoosterAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CVX_V1_BASE_REWARD_POOL",
                version: 310,
                initCode: type(ConvexV1BaseRewardPoolAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CAMELOT_V3_ROUTER",
                version: 310,
                initCode: type(CamelotV3Adapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CURVE_V1_2ASSETS",
                version: 310,
                initCode: type(CurveV1Adapter2Assets).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CURVE_V1_3ASSETS",
                version: 310,
                initCode: type(CurveV1Adapter3Assets).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CURVE_V1_4ASSETS",
                version: 310,
                initCode: type(CurveV1Adapter4Assets).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CURVE_STABLE_NG",
                version: 310,
                initCode: type(CurveV1AdapterStableNG).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::CURVE_V1_STECRV_POOL",
                version: 310,
                initCode: type(CurveV1AdapterStETH).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::EQUALIZER_ROUTER",
                version: 310,
                initCode: type(EqualizerRouterAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::ERC4626_VAULT",
                version: 310,
                initCode: type(ERC4626Adapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({contractType: "ADAPTER::LIDO_V1", version: 310, initCode: type(LidoV1Adapter).creationCode})
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::LIDO_WSTETH_V1",
                version: 310,
                initCode: type(LidoV1Adapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::MELLOW_ERC4626_VAULT",
                version: 310,
                initCode: type(Mellow4626VaultAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::MELLOW_LRT_VAULT",
                version: 310,
                initCode: type(MellowVaultAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::PENDLE_ROUTER",
                version: 310,
                initCode: type(PendleRouterAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::DAI_USDS_EXCHANGE",
                version: 310,
                initCode: type(DaiUsdsAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::STAKING_REWARDS",
                version: 310,
                initCode: type(StakingRewardsAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::UNISWAP_V2_ROUTER",
                version: 310,
                initCode: type(UniswapV2Adapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::UNISWAP_V3_ROUTER",
                version: 310,
                initCode: type(UniswapV3Adapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::VELODROME_V2_ROUTER",
                version: 310,
                initCode: type(VelodromeV2RouterAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::YEARN_V2",
                version: 310,
                initCode: type(YearnV2Adapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::ZIRCUIT_POOL",
                version: 310,
                initCode: type(ZircuitPoolAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::TRADERJOE_ROUTER",
                version: 310,
                initCode: type(TraderJoeRouterAdapter).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "ADAPTER::INFRARED_VAULT",
                version: 310,
                initCode: type(InfraredVaultAdapter).creationCode
            })
        );

        /// Price Feeds

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::BOUNDED",
                version: 310,
                initCode: type(BoundedPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::COMPOSITE",
                version: 310,
                initCode: type(CompositePriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({contractType: "PRICE_FEED::ZERO", version: 310, initCode: type(ZeroPriceFeed).creationCode})
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::CONSTANT",
                version: 310,
                initCode: type(ConstantPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::BALANCER_STABLE",
                version: 310,
                initCode: type(BPTStablePriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::BALANCER_WEIGHTED",
                version: 310,
                initCode: type(BPTWeightedPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::CURVE_STABLE",
                version: 310,
                initCode: type(CurveStableLPPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::CURVE_CRYPTO",
                version: 310,
                initCode: type(CurveCryptoLPPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::CURVE_TWAP",
                version: 310,
                initCode: type(CurveTWAPPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::WSTETH",
                version: 310,
                initCode: type(WstETHPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::YEARN",
                version: 310,
                initCode: type(YearnPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::ERC4626",
                version: 310,
                initCode: type(ERC4626PriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::MELLOW_LRT",
                version: 310,
                initCode: type(MellowLRTPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::PENDLE_PT_TWAP",
                version: 310,
                initCode: type(PendleTWAPPTPriceFeed).creationCode
            })
        );

        _configs.push(
            BytecodeConfig({contractType: "PRICE_FEED::PYTH", version: 310, initCode: type(PythPriceFeed).creationCode})
        );

        _configs.push(
            BytecodeConfig({
                contractType: "PRICE_FEED::REDSTONE",
                version: 310,
                initCode: type(RedstonePriceFeed).creationCode
            })
        );
    }

    function configs() public view returns (BytecodeConfig[] memory) {
        return _configs;
    }
}
