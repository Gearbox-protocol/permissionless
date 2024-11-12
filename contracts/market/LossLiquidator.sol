// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {Pausable} from "@openzeppelin/contracts/security/Pausable.sol";
import {SafeERC20} from "@1inch/solidity-utils/contracts/libraries/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";
import {PriceFeedValidationTrait} from "@gearbox-protocol/core-v3/contracts/traits/PriceFeedValidationTrait.sol";
import {BitMask} from "@gearbox-protocol/core-v3/contracts/libraries/BitMask.sol";
import {
    PERCENTAGE_FACTOR, RAY, UNDERLYING_TOKEN_MASK
} from "@gearbox-protocol/core-v3/contracts/libraries/Constants.sol";

import {
    ICreditManagerV3,
    CollateralDebtData,
    CollateralCalcTask
} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {ICreditFacadeV3, MultiCall} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditFacadeV3Multicall} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3Multicall.sol";
import {
    IPriceOracleV3,
    PriceUpdate,
    PriceFeedParams
} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {ICreditAccountV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditAccountV3.sol";
import {IUpdatablePriceFeed} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IPriceFeed.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPriceFeedStore} from "../interfaces/IPriceFeedStore.sol";

interface ILossLiquidatorExceptions {
    /// @dev Thrown when a bad-debt liquidation violates policy
    error PolicyViolatingLiquidationException();

    /// @dev Thrown when liquidation calls contain withdrawals to an address other than emergency liquidator contract
    error WithdrawalToExternalAddressException();

    /// @dev Thrown when a non-whitelisted address attempts to call an access-restricted function
    error CallerNotWhitelistedException();

    /// @dev Thrown when attempting to set an alias for an address that is not a valid token
    error IncorrectTokenContractException();
}

interface ILossLiquidatorEvents {
    /// @dev Emitted when a new account is added to / removed from the whitelist
    event SetWhitelistedStatus(address indexed account, bool newStatus);

    /// @dev Emitted when an alias for a token is set
    event SetAlias(address indexed token, address indexed priceFeed);

    /// @dev Emitted when public liquidations are temporarily allowed
    event AllowPublicLiquidations(uint256 indexed start, uint256 indexed end);

    /// @dev Emitted when policy enforcement is temporarily disabled for whitelisted accounts
    event AllowPolicyWaiveForWhitelisted(uint256 indexed start, uint256 indexed end);
}

contract LossLiquidator is
    ACLTrait,
    PriceFeedValidationTrait,
    Pausable,
    ILossLiquidatorExceptions,
    ILossLiquidatorEvents
{
    using BitMask for uint256;
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Address of the price feed store contract
    address public immutable priceFeedStore;

    /// @notice Timestamp until which liquidations by non-whitelisted addresses are allowed
    uint40 public publicLiquidationsAllowedUntil;

    /// @notice Timestamp until which liquidations by whitelisted accounts are not checked against policy
    uint40 public policyWaivedForWhitelistUntil;

    /// @notice Map from token address to its substitute price feed for the purposes of bad debt liquidations, including additional
    ///         price feed parameters
    mapping(address => PriceFeedParams) public aliasPriceFeeds;

    /// @dev Set of all tokens that have aliases set for them
    EnumerableSet.AddressSet internal aliasedTokens;

    /// @dev Set of all whitelisted accounts in the contract
    EnumerableSet.AddressSet internal whitelistedAccounts;

    constructor(address _acl, address _priceFeedStore) ACLTrait(_acl) {
        priceFeedStore = _priceFeedStore;
    }

    modifier whitelistedOnly() {
        if (!whitelistedAccounts.contains(msg.sender)) revert CallerNotWhitelistedException();
        _;
    }

    /// @dev Checks that either the temporary non-whitelisted mode is enabled, or the msg.sender is whitelised
    modifier timedNonWhitelistedOnly() {
        if (block.timestamp > publicLiquidationsAllowedUntil && !whitelistedAccounts.contains(msg.sender)) {
            revert CallerNotWhitelistedException();
        }
        _;
    }

    /// @dev Checks that all withdrawals are sent to this contract, reverts if not
    modifier checkWithdrawalDestinations(address creditFacade, MultiCall[] calldata calls) {
        _;
    }

    /// @notice Liquidates a credit account, while checking restrictions on liquidations during pause
    function liquidateCreditAccount(
        address creditManager,
        address creditAccount,
        MultiCall[] calldata calls,
        PriceUpdate[] memory priceUpdates
    ) external whenNotPaused timedNonWhitelistedOnly {
        address creditFacade = ICreditManagerV3(creditManager).creditFacade();
        address priceOracle = ICreditManagerV3(creditManager).priceOracle();

        _applyPriceFeedUpdates(priceUpdates);
        _checkPolicy(creditManager, creditFacade, creditAccount, priceOracle, calls);

        ICreditFacadeV3(creditFacade).liquidateCreditAccount(creditAccount, address(this), calls);
    }

    /// @notice Liquidates a credit account with max underlying approval, allowing to buy collateral with DAO funds
    /// @dev Can be exploited by account owners when open to everyone, and thus is only allowed for whitelisted addresses
    /// @dev This can be used to liquidate accounts when there is bad on-chain liquidity for the asset in the moment, but it is
    ///      expected that collateral can be disposed of off-chain or liquidity restores in the future
    function liquidateCreditAccountWithApproval(
        address creditManager,
        address creditAccount,
        MultiCall[] calldata calls,
        PriceUpdate[] memory priceUpdates
    ) external whenNotPaused whitelistedOnly {
        address creditFacade = ICreditManagerV3(creditManager).creditFacade();
        address priceOracle = ICreditManagerV3(creditManager).priceOracle();

        _applyPriceFeedUpdates(priceUpdates);
        _checkPolicy(creditManager, creditFacade, creditAccount, priceOracle, calls);

        address underlying = ICreditManagerV3(creditManager).underlying();
        IERC20(underlying).forceApprove(creditManager, type(uint256).max);
        ICreditFacadeV3(creditFacade).liquidateCreditAccount(creditAccount, address(this), calls);
        IERC20(underlying).forceApprove(creditManager, 1);
    }

    /// @dev Checks that the liquidation satisfies policy
    /// @dev The general policy for liquidations is that when the CF is paused and there is bad debt -
    ///      we check whether the account is liquidatable with prices computed from aliases. I.e. when an
    ///      alias is set for a token, we use the price of the alias to compute the TWV instead of the token's own price.
    ///      This allows to, for example, set a pegged assets price feed (only for the purposes of bad debt liquidations) to
    ///      the feed of its peg target (e.g., ETH for LRTs). This allows to avoid immediately liquidating accounts that went
    ///      unhealthy due to a short-term peg. This policy can be overriden if bad debt liquidations are
    ///      deemed to be actually justified.
    function _checkPolicy(
        address creditManager,
        address creditFacade,
        address creditAccount,
        address priceOracle,
        MultiCall[] calldata calls
    ) internal view {
        _checkWithdrawalsDestination(creditFacade, calls);

        CollateralDebtData memory cdd =
            ICreditManagerV3(creditManager).calcDebtAndCollateral(creditAccount, CollateralCalcTask.DEBT_COLLATERAL);

        if (
            _hasBadDebt(creditManager, cdd)
                && !(_isPolicyWaived(msg.sender) || _isLiquidatableAliased(creditManager, creditAccount, priceOracle, cdd))
        ) {
            revert PolicyViolatingLiquidationException();
        }
    }

    /// @dev Returns whether the msg.sender can liquidate in lieu of policy
    function _isPolicyWaived(address account) internal view returns (bool) {
        return whitelistedAccounts.contains(account) && block.timestamp <= policyWaivedForWhitelistUntil;
    }

    /// @dev Returns whether the account is in bad debt
    function _hasBadDebt(address creditManager, CollateralDebtData memory cdd) internal view returns (bool) {
        (,, uint16 liquidationDiscount,,) = ICreditManagerV3(creditManager).fees();
        return cdd.totalValue * liquidationDiscount < (cdd.debt + cdd.accruedInterest) * PERCENTAGE_FACTOR;
    }

    /// @dev Returns whether the account is liquidatable after replacing collateral token prices with their
    ///      respective alias prices
    function _isLiquidatableAliased(
        address creditManager,
        address creditAccount,
        address priceOracle,
        CollateralDebtData memory cdd
    ) internal view returns (bool) {
        uint256 remainingTokensMask = cdd.enabledTokensMask.disable(UNDERLYING_TOKEN_MASK);
        if (remainingTokensMask == 0) return cdd.twvUSD < cdd.totalDebtUSD;

        uint256 twvUSDAliased = cdd.twvUSD;

        uint256 underlyingPriceRAY = _convertToUSD(priceOracle, ICreditManagerV3(creditManager).underlying(), RAY);

        while (remainingTokensMask != 0) {
            uint256 tokenMask = remainingTokensMask & uint256(-int256(remainingTokensMask));
            remainingTokensMask ^= tokenMask;

            (address token, uint16 tokenLT) = ICreditManagerV3(creditManager).collateralTokenByMask(tokenMask);
            PriceFeedParams memory aliasParams = aliasPriceFeeds[token];

            if (aliasParams.priceFeed == address(0)) continue;

            uint256 balance = IERC20(token).safeBalanceOf({account: creditAccount});
            uint256 quotaUSD;
            {
                (uint256 quota,) = IPoolQuotaKeeperV3(cdd._poolQuotaKeeper).getQuota(creditAccount, token);
                quotaUSD = quota * underlyingPriceRAY / RAY;
            }

            twvUSDAliased = _adjustForAlias(token, priceOracle, aliasParams, twvUSDAliased, quotaUSD, balance, tokenLT);
        }

        return twvUSDAliased < cdd.totalDebtUSD;
    }

    /// @dev Checks that the provided calldata has all withdrawals sent to this contract
    function _checkWithdrawalsDestination(address creditFacade, MultiCall[] calldata calls) internal view {
        uint256 len = calls.length;

        for (uint256 i = 0; i < len;) {
            if (
                calls[i].target == creditFacade
                    && bytes4(calls[i].callData) == ICreditFacadeV3Multicall.withdrawCollateral.selector
            ) {
                (,, address to) = abi.decode(calls[i].callData[4:], (address, uint256, address));

                if (to != address(this)) revert WithdrawalToExternalAddressException();
            }

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Applies price feed updates
    function _applyPriceFeedUpdates(PriceUpdate[] memory priceUpdates) internal {
        uint256 len = priceUpdates.length;
        for (uint256 i = 0; i < len;) {
            IUpdatablePriceFeed(priceUpdates[i].priceFeed).updatePrice(priceUpdates[i].data);

            unchecked {
                ++i;
            }
        }
    }

    /// @dev Returns the twvUSD value where the token's WV is computed based on alias feed instead of main feed
    function _adjustForAlias(
        address token,
        address priceOracle,
        PriceFeedParams memory aliasParams,
        uint256 twvUSD,
        uint256 quotaUSD,
        uint256 balance,
        uint16 tokenLT
    ) internal view returns (uint256) {
        uint256 vwNormal = Math.min(_convertToUSD(priceOracle, token, balance) * tokenLT / PERCENTAGE_FACTOR, quotaUSD);
        uint256 vwAliased = Math.min(_convertToUSDAlias(aliasParams, balance) * tokenLT / PERCENTAGE_FACTOR, quotaUSD);

        return twvUSD + vwAliased - vwNormal;
    }

    /// @dev Converts token amount to USD using its current main price feed from the price oracle
    function _convertToUSD(address priceOracle, address token, uint256 amount) internal view returns (uint256) {
        return IPriceOracleV3(priceOracle).convertToUSD(amount, token);
    }

    /// @dev Converts token amount to USD using its alias price feed
    function _convertToUSDAlias(PriceFeedParams memory aliasParams, uint256 amount) internal view returns (uint256) {
        int256 price = _getValidatedPrice(aliasParams.priceFeed, aliasParams.stalenessPeriod, aliasParams.skipCheck);
        return uint256(price) * amount / (10 ** aliasParams.tokenDecimals);
    }

    /// @notice Returns current whitelisted accounts
    function getWhitelistedAccounts() external view returns (address[] memory) {
        return whitelistedAccounts.values();
    }

    /// @notice Returns aliased tokens and their respective alias price feed
    function getAliasedTokens() external view returns (address[] memory tokens, address[] memory priceFeeds) {
        tokens = aliasedTokens.values();

        uint256 len = tokens.length;

        priceFeeds = new address[](len);
        for (uint256 i = 0; i < len; ++i) {
            priceFeeds[i] = aliasPriceFeeds[tokens[i]].priceFeed;
        }
    }

    /// @notice Returns the list of price feeds that need to return a valid price to
    ///         perform a bad debt liquidation for an account
    function getRequiredPriceFeeds(address creditAccount) external view returns (address[] memory priceFeeds) {
        address creditManager = ICreditAccountV3(creditAccount).creditManager();
        uint256 remainingTokensMask = ICreditManagerV3(creditManager).enabledTokensMaskOf(creditAccount);
        address priceOracle = ICreditManagerV3(creditManager).priceOracle();

        priceFeeds = new address[](remainingTokensMask.calcEnabledTokens());
        uint256 k = 0;

        while (remainingTokensMask != 0) {
            uint256 tokenMask = remainingTokensMask.lsbMask();
            remainingTokensMask ^= tokenMask;

            (address token,) = ICreditManagerV3(creditManager).collateralTokenByMask(tokenMask);

            address aliasPriceFeed = aliasPriceFeeds[token].priceFeed;

            if (aliasPriceFeed != address(0)) {
                priceFeeds[k] = aliasPriceFeed;
            } else {
                priceFeeds[k] = IPriceOracleV3(priceOracle).priceFeeds(token);
            }

            unchecked {
                ++k;
            }
        }
    }

    /// @notice Sends funds accumulated from liquidations to a specified address
    function withdrawFunds(address token, uint256 amount, address to) external configuratorOnly {
        IERC20(token).safeTransfer(to, amount);
    }

    /// @notice Sets the status of an account as whitelisted
    function setWhitelistedAccount(address account, bool newStatus) external configuratorOnly {
        bool whitelistedStatus = whitelistedAccounts.contains(account);

        if (newStatus != whitelistedStatus) {
            if (newStatus) {
                whitelistedAccounts.add(account);
            } else {
                whitelistedAccounts.remove(account);
            }
            emit SetWhitelistedStatus(account, newStatus);
        }
    }

    /// @notice Sets alias for a token and adds/removes it from the set of aliased tokens
    function setAliasPriceFeed(address token, address priceFeed) external configuratorOnly {
        PriceFeedParams storage pfParams = aliasPriceFeeds[token];

        address currentPriceFeed = pfParams.priceFeed;

        if (currentPriceFeed != priceFeed) {
            if (priceFeed != address(0)) {
                uint32 stalenessPeriod = IPriceFeedStore(priceFeedStore).getStalenessPeriod(priceFeed);

                bool skipCheck = _validatePriceFeed(priceFeed, stalenessPeriod);

                pfParams.priceFeed = priceFeed;
                pfParams.stalenessPeriod = stalenessPeriod;
                pfParams.skipCheck = skipCheck;
                pfParams.tokenDecimals = _validateToken(token);

                aliasedTokens.add(token);
            } else {
                delete aliasPriceFeeds[token];
                aliasedTokens.remove(token);
            }

            emit SetAlias(token, priceFeed);
        }
    }

    /// @dev Validates that `token` is a contract that returns `decimals` within allowed range
    function _validateToken(address token) internal view returns (uint8 decimals) {
        if (!Address.isContract(token)) revert IncorrectTokenContractException();
        try IERC20Metadata(token).decimals() returns (uint8 _decimals) {
            if (_decimals == 0 || _decimals > 18) revert IncorrectTokenContractException();
            decimals = _decimals;
        } catch {
            revert IncorrectTokenContractException();
        }
    }

    /// @notice Allows non-whitelisted actors to liquidate accounts during pause for a given duration
    function allowTemporaryPublicLiquidations(uint256 duration) external configuratorOnly {
        publicLiquidationsAllowedUntil = uint40(block.timestamp + duration);
        emit AllowPublicLiquidations(block.timestamp, block.timestamp + duration);
    }

    /// @notice Allows whitelisted actors to liquidate bad debt accounts even when the policy is not satisfied, for a given duration
    function allowTemporaryPolicyWaive(uint256 duration) external configuratorOnly {
        policyWaivedForWhitelistUntil = uint40(block.timestamp + duration);
        emit AllowPolicyWaiveForWhitelisted(block.timestamp, block.timestamp + duration);
    }
}
