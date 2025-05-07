// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {BCRHelpers} from "../contracts/test/helpers/BCRHelpers.sol";
import {InstanceManager} from "../contracts/instance/InstanceManager.sol";
import {BytecodeRepository} from "../contracts/global/BytecodeRepository.sol";
import {Bytecode, AuditReport} from "../contracts/interfaces/Types.sol";
import {BytecodeConfigs, BytecodeConfig} from "./BytecodeConfig.sol";

import {VmSafe} from "forge-std/Vm.sol";
import "forge-std/Script.sol";

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

address constant IM = 0x77777777144339Bdc3aCceE992D8d4D31734CB2e;

contract AddBytecode is Script, BCRHelpers {
    address ccmProxy;

    BytecodeConfigs bc;

    function run() external {
        bc = new BytecodeConfigs();
        bytecodeRepository = InstanceManager(IM).bytecodeRepository();
        ccmProxy = InstanceManager(IM).crossChainGovernanceProxy();

        VmSafe.Wallet memory auditor = vm.createWallet(uint256(keccak256(abi.encodePacked("auditor"))));

        vm.startBroadcast(auditor.addr);

        _startPrankOrBroadcast(ccmProxy);
        BytecodeRepository(bytecodeRepository).addAuditor(auditor.addr, "auditor");
        _stopPrankOrBroadcast();

        BytecodeConfig[] memory bcs = bc.configs();

        for (uint256 i = 0; i < bcs.length; i++) {
            _safeUploadBytecode(auditor, bcs[i]);
        }

        vm.stopBroadcast();
    }

    function _safeUploadBytecode(VmSafe.Wallet memory auditor, BytecodeConfig memory bc) internal {
        if (BytecodeRepository(bytecodeRepository).getAllowedBytecodeHash(bc.contractType, bc.version) == bytes32(0)) {
            emit log_bytes32(bc.contractType);
            _uploadByteCodeAndSign(auditor, auditor, bc.initCode, bc.contractType, bc.version);
        }
    }
}
