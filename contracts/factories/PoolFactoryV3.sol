// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {AbstractFactory} from "./AbstractFactory.sol";
import {
    AP_POOL,
    AP_POOL_QUOTA_KEEPER,
    AP_POOL_RATE_KEEPER,
    AP_DEGEN_NFT,
    AP_POOL_FACTORY,
    DOMAIN_POOL
} from "../libraries/ContractLiterals.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";

import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";
import {CallBuilder} from "../libraries/CallBuilder.sol";

import {LibString} from "@solady/utils/LibString.sol";

// PoolFactoryV3 is responsible for creating pools and their management
contract PoolFactoryV3 is AbstractFactory, IVersion {
    using LibString for string;
    using LibString for bytes32;
    using CallBuilder for Call;

    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_POOL_FACTORY;

    //
    // ERRORS
    //

    // Thrown if a credit manager with non-zero borrowed amount is attempted to be removed
    error CantRemoveNonEmptyCreditSuiteException(address creditManager);

    // Thrown if attempting to remove a market that still has active positions
    error CantRemoveNonEmptyMarketException(address pool);

    constructor(address _marketConfigurator) AbstractFactory(_marketConfigurator) {}

    function deployPool(address underlying, address interestRateModel, string calldata name, string calldata symbol)
        external
        marketConfiguratorOnly
        returns (address pool, Call[] memory onInstallOps)
    {
        address acl = ACLTrait(msg.sender).acl();

        //
        pool = _deployPool(underlying, acl, interestRateModel, totalDebtLimit, name, symbol, version, _salt);
        address poolQuotaKeeper = _deployPoolQuotaKeeper(pool, version, salt);

        // Inflation attack protection
        if (IERC20(underlying).balanceOf(address(this)) < 1e5) revert InsufficientBalanceException();
        IERC20(underlying).forceApprove(pool, 1e5);
        IPoolV3(pool).deposit(1e5, address(0xdead));

        onInstallOps = Call.build(_setPoolQuotaKeeper(pool, poolQuotaKeeper));
    }

    //
    // MODULAR HOOKS
    //

    // @dev Hook which is called when new token is added to the pool
    // @param pool - pool address
    // @param token - token address
    // @param priceFeed - price feed address
    // @return calls - array of calls to be executed
    function onAddToken(address pool, address token, address priceFeed) external view returns (Call[] memory calls) {}

    // @dev Hook which is called when interest model is updated
    // @param pool - pool address
    // @param newModel - new interest model address
    // @return calls - array of calls to be executed
    function onUpdateInterestModel(address pool, address newModel) external view returns (Call[] memory calls) {
        calls = Call.build(_setInterestRateModel(pool, newModel));
    }

    // @dev Hook which is called when new credit manager is created
    // @param newCreditManager - new credit manager address
    // @return calls - array of calls to be executed
    function onAddCreditManager(address pool, address newCreditManager) external view returns (Call[] memory calls) {}

    /**
     * @notice Hook that executes when a creditManager is removed from the market.
     * It checks
     * @param _creditManager The address of the creditManager being removed.
     * @return calls An array of Call structs to be executed, setting the credit manager's debt limit to zero.
     */
    function onRemoveCreditManager(address _creditManager) external view returns (Call[] memory calls) {
        address pool = ICreditManagerV3(_creditManager).pool();

        if (IPoolV3(pool).creditManagerBorrowed(creditManager) != 0) {
            revert CantRemoveNonEmptyCreditSuiteException(creditManager);
        }

        calls = Call.build(_setCreditManagerDebtLimit(pool, _creditManager, 0));
    }

    /**
     * @notice Hook that executes when the rate keeper is updated for a pool
     * @dev This hook is used to update the rate keeper in the pool quota keeper
     * @param pool The address of the pool
     * @param rateKeeper The address of the new rate keeper
     * @return calls An array of Call structs to be executed
     */
    function onUpdateRateKeeper(address pool, address rateKeeper)
        external
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {
        calls = Call.build(_setRateKeeper(IPoolV3(pool).poolQuotaKeeper(), rateKeeper));
    }

    function onUpdatePriceOracle(address newPriceOracle)
        external
        marketConfiguratorOnly
        returns (Call[] memory calls)
    {}

    function onRemoveMarket(address pool) external override returns (Call[] memory calls) {
        if (IPoolV3(pool).totalBorrowed() != 0 || _creditManagers(pool).length != 0) {
            revert CantRemoveNonEmptyMarketException(pool);
        }

        calls = Call.build(
            // set total debt limit to 0
            _setTotalDebtLimit(pool, 0),
            // set withdraw fee to 0
            _setWithdrawFee(pool, 0)
        );
    }

    // @dev Hook which is called when price feed is updated
    // Used as verification for price oracle, to prove that price is not zero
    // for underlying or any other collateral token with non-zero quota
    // @param pool - pool address
    // @param token - token address
    // @param priceFeed - price feed address
    // @return calls - array of calls to be executed
    function onSetPriceFeed(address pool, address token, address priceFeed)
        external
        view
        returns (Call[] memory calls)
    {
        // Check that underlying price is non-zero
        if (
            (IPriceOracle(priceOracle).getPrice(token) == 0)
                && (token == IPoolV3(pool).asset() || _quota(pool, token) != 0)
        ) revert IncorrectPriceException();
    }

    //
    function _deployPool(
        address martketConfigurator,
        address underlying,
        address acl,
        address interestRateModel,
        uint256 totalDebtLimit,
        string calldata name,
        string calldata symbol
    ) internal returns (address pool) {
        bytes memory constructorParams = abi.encode(acl, underlying, interestRateModel, totalDebtLimit, name, symbol);
        bytes32 postfix = IBytecodeRepository(bytecodeRepository).hasTokenSpecificPrefix(underlying);

        return IBytecodeRepository(bytecodeRepository).deployByDomain(
            DOMAIN_POOL, postfix, version, constructorParams, bytes32(marketConfigurator)
        );
    }

    function _deployPoolQuotaKeeper(address pool, uint256 _version, bytes32 _salt) internal returns (address pqk) {
        bytes memory constructorParams = abi.encode(pool);
        return IBytecodeRepository(bytecodeRepository).deploy(AP_POOL_QUOTA_KEEPER, _version, constructorParams, _salt);
    }

    // function deployDegenNFT(
    //     address acl,
    //     address contractRegister,
    //     string memory accessType,
    //     uint256 _version,
    //     bytes32 _salt
    // ) external returns (address rateKeeper) {
    //     bytes memory constructorParams = abi.encode(acl, contractRegister);
    //     return IBytecodeRepository(bytecodeRepository).deploy(
    //         string.concat(AP_DEGEN_NFT.fromSmallString(), accessType).toSmallString(),
    //         _version,
    //         constructorParams,
    //         _salt
    //     );
    // }

    //
    // INTERNALS
    //
    function _quota(address pool, address token) internal view returns (uint96 quota) {
        (,,, quota,,) = IPoolQuotaKeeperV3(_quotaKeeper(pool)).getTokenQuotaParams(token);
    }

    function _quotaKeeper(address pool) internal view returns (address) {
        return IPoolV3(pool).poolQuotaKeeper();
    }

    function _setPoolQuotaKeeper(address pool, address quotaKeeper) internal pure returns (Call memory call) {
        call = Call({target: pool, callData: abi.encodeCall(IPoolV3.setPoolQuotaKeeper, quotaKeeper)});
    }

    function _setCreditManagerDebtLimit(address pool, address _creditManager, uint256 limit)
        internal
        pure
        returns (Call memory call)
    {
        call =
            Call({target: pool, callData: abi.encodeCall(IPoolV3.setCreditManagerDebtLimit, (_creditManager, limit))});
    }

    function _setRateKeeper(address quotaKeeper, address newKeeper) internal pure returns (Call memory call) {
        call = Call({target: quotaKeeper, callData: abi.encodeCall(IPoolQuotaKeeperV3.setGauge, (rateKeeper))});
    }

    function _setInterestRateModel(address pool, address newModel) internal pure returns (Call memory call) {
        call = Call({target: pool, callData: abi.encodeCall(IPoolV3.setInterestRateModel, (newModel))});
    }

    function _setTotalDebtLimit(address pool, uint256 limit) internal pure returns (Call memory call) {
        call = Call({target: pool, callData: abi.encodeCall(IPoolV3.setTotalDebtLimit, (limit))});
    }

    function _setWithdrawFee(address pool, uint256 fee) internal pure returns (Call memory call) {
        call = Call({target: pool, callData: abi.encodeCall(IPoolV3.setWithdrawFee, (fee))});
    }
}
