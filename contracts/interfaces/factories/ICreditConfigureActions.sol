// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.

import {CreditFacadeParams} from "./ICreditFactory.sol";
import {DeployParams} from "../Types.sol";

interface ICreditConfigureActions {
    function upgradeCreditConfigurator() external;
    function upgradeCreditFacade(CreditFacadeParams calldata params) external;
    function allowAdapter(DeployParams calldata params) external;
    function forbidAdapter(address adapter) external;
    function configureAdapterFor(address targetContract, bytes calldata data) external;
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
