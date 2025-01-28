// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.

interface IPoolConfigureActions {
    function setTotalDebtLimit(uint256 limit) external;
    function setCreditManagerDebtLimit(address creditManager, uint256 limit) external;
    function setTokenLimit(address token, uint96 limit) external;
    function setTokenQuotaIncreaseFee(address token, uint16 fee) external;
    function pause() external;
    function unpause() external;
}
