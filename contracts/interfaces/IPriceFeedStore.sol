// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

interface IPriceFeedStore {
    function getPriceFeeds(address token) external view returns (address[] memory);
    function isAllowedPriceFeed(address token, address priceFeed) external view returns (bool);
    function getStalenessPeriod(address priceFeed) external view returns (uint32);
}
