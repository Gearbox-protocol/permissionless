// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.

interface ICreditEmergencyConfigureActions {
    function forbidAdapter(address adapter) external;
    function forbidToken(address token) external;
    function forbidBorrowing() external;
    function pause() external;
}
