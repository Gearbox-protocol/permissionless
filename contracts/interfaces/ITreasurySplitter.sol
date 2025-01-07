// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.0;

struct Split {
    bool initialized;
    address[] receivers;
    uint16[] proportions;
}

/// @title Treasury splitter
interface ITreasurySplitter {
    /// @notice Thrown when attempting to set a split with different-sized receiver and proportion arrays
    error SplitArraysDifferentLengthException();

    /// @notice Thrown when attempting to set a split that doesn't have proportions summing to 1
    error PropotionSumIncorrectException();

    /// @notice Thrown when attempting to distribute a token for which a split is not defined
    error UndefinedSplitException();

    /// @notice Emitted when a new default split is set
    event SetDefaultSplit(address[] receivers, uint16[] proportions);

    /// @notice Emitted when a new token-specific split is set
    event SetTokenSplit(address indexed token, address[] receivers, uint16[] proportions);

    /// @notice Emitted whan a token is withdrawn to another address
    event WithdrawToken(address indexed token, address indexed to, uint256 withdrawnAmount);

    /// @notice Emitted when tokens are distributed
    event DistributeToken(address indexed token, uint256 distributedAmount);

    function distribute(address token) external;

    function tokenSplits(address token) external view returns (Split memory);

    function defaultSplit() external view returns (Split memory);

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function setTokenSplit(address token, address[] memory receivers, uint16[] memory proportions) external;

    function setDefaultSplit(address[] memory receivers, uint16[] memory proportions) external;

    function withdrawToken(address token, address to, uint256 amount) external;
}
