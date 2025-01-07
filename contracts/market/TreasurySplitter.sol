// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {ITreasurySplitter, Split} from "../interfaces/ITreasurySplitter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {PERCENTAGE_FACTOR} from "@gearbox-protocol/core-v3/contracts/libraries/Constants.sol";

contract TreasurySplitter is Ownable, ITreasurySplitter {
    using SafeERC20 for IERC20;

    /// @notice Default split for this splitter. Used when no specific split is set for the distributed token.
    Split internal _defaultSplit;

    /// @notice Mapping from token address to the associated split. Used to set specific splits for certain tokens.
    mapping(address => Split) internal _tokenSplits;

    /// @notice Mapping from token address to its last observed balance for this contract
    mapping(address => uint256) public lastBalance;

    /// @notice Returns a Split struct for a particular token
    function tokenSplits(address token) external view returns (Split memory split) {
        return _tokenSplits[token];
    }

    /// @notice Returns the default Split struct
    function defaultSplit() external view returns (Split memory) {
        return _defaultSplit;
    }

    /// @notice Distributes any new amount sent to the contract according to either the token-specific or default split.
    /// @param token Token to distribute
    function distribute(address token) external {
        Split memory split;

        if (_tokenSplits[token].initialized) {
            split = _tokenSplits[token];
        } else if (_defaultSplit.initialized) {
            split = _defaultSplit;
        } else {
            revert UndefinedSplitException();
        }

        uint256 len = split.receivers.length;

        uint256 balanceDiff = IERC20(token).balanceOf(address(this)) - lastBalance[token];

        for (uint256 i = 0; i < len; ++i) {
            address receiver = split.receivers[i];
            uint16 proportion = split.proportions[i];

            if (receiver != address(this)) {
                IERC20(token).safeTransfer(receiver, proportion * balanceDiff / PERCENTAGE_FACTOR);
            }
        }

        lastBalance[token] = IERC20(token).balanceOf(address(this));

        emit DistributeToken(token, balanceDiff);
    }

    /// @notice Sets a split for a specific token
    function setTokenSplit(address token, address[] memory receivers, uint16[] memory proportions) external onlyOwner {
        _setSplit(_tokenSplits[token], receivers, proportions);

        emit SetTokenSplit(token, receivers, proportions);
    }

    /// @notice Sets a default split used for tokens that don't have a specific split
    function setDefaultSplit(address[] memory receivers, uint16[] memory proportions) external onlyOwner {
        _setSplit(_defaultSplit, receivers, proportions);

        emit SetDefaultSplit(receivers, proportions);
    }

    /// @dev Internal logic for `setTokenSplit` and `setDefaultSplit`
    function _setSplit(Split storage _split, address[] memory receivers, uint16[] memory proportions) internal {
        if (receivers.length != proportions.length) revert SplitArraysDifferentLengthException();

        uint256 propSum = 0;

        for (uint256 i = 0; i < proportions.length; ++i) {
            propSum += proportions[i];
        }

        if (propSum != PERCENTAGE_FACTOR) revert PropotionSumIncorrectException();

        _split.initialized = true;
        _split.receivers = receivers;
        _split.proportions = proportions;
    }

    /// @notice Withdraws an amount of a token to another address
    function withdrawToken(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(to, amount);
        lastBalance[token] = IERC20(token).balanceOf(address(this));

        emit WithdrawToken(token, to, amount);
    }
}
