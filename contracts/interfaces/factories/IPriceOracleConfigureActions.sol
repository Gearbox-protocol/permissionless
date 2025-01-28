// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.

interface IPriceOracleConfigureActions {
    function setPriceFeed(address token, address priceFeed) external;
    function setReservePriceFeed(address token, address priceFeed) external;
}
