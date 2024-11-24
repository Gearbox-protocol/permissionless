// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {Call, DeployResult} from "../Types.sol";
import {IConfiguratingFactory} from "./IConfiguratingFactory.sol";

interface ICreditFactory is IVersion, IConfiguratingFactory {
    function deployCreditSuite(address pool, bytes calldata encodedParams) external returns (DeployResult memory);

    function onUpdatePriceOracle(address creditManager, address newPriceOracle, address oldPriceOracle)
        external
        returns (Call[] memory calls);

    function onUpdateLossLiquidator(address creditManager, address newLossLiquidator, address oldLossLiquidator)
        external
        returns (Call[] memory calls);
}
