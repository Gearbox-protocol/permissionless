// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@1inch/solidity-utils/contracts/libraries/SafeERC20.sol";

import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {MarketHookFactory} from "./MarketHookFactory.sol";
import {
    AP_POOL,
    AP_POOL_QUOTA_KEEPER,
    AP_POOL_RATE_KEEPER,
    AP_DEGEN_NFT,
    AP_POOL_FACTORY,
    AP_DEFAULT_IRM,
    NO_VERSION_CONTROL,
    DOMAIN_POOL
} from "../libraries/ContractLiterals.sol";
import {IBytecodeRepository} from "../interfaces/IBytecodeRepository.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPriceOracleV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {DeployResult} from "../interfaces/Types.sol";
import {IPoolFactory} from "../interfaces/IPoolFactory.sol";
import {Call, DeployResult} from "../interfaces/Types.sol";
import {IMarketHooks} from "../interfaces/IMarketHooks.sol";
import {IContractsRegister} from "../interfaces/extensions/IContractsRegister.sol";
import {
    IncorrectPriceException,
    InsufficientBalanceException
} from "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";

// PoolFactoryV3 is responsible for creating pools and their management

contract PoolFactoryV3 is AbstractFactory, MarketHookFactory, IPoolFactory {
    using SafeERC20 for IERC20;
    using CallBuilder for Call;

    /// @notice Contract version
    uint256 public constant override version = 3_10;
    bytes32 public constant override contractType = AP_POOL_FACTORY;

    address public immutable defaultInterestRateModel;

    //
    // ERRORS
    //

    // Thrown if a credit manager with non-zero borrowed amount is attempted to be removed
    error CantRemoveNonEmptyCreditSuiteException(address creditManager);

    // Thrown if attempting to remove a market that still has active positions
    error CantShutdownNonEmptyMarketException(address pool);

    constructor(address _addressProvider) AbstractFactory(_addressProvider) {
        defaultInterestRateModel =
            IAddressProvider(_addressProvider).getAddressOrRevert(AP_DEFAULT_IRM, NO_VERSION_CONTROL);
    }

    // QUESTION: keep minimal needed params or provide acl & contractsRegister?
    function deployPool(address underlying, string calldata name, string calldata symbol)
        external
        override
        marketConfiguratorOnly
        returns (DeployResult memory)
    {
        // Get required addresses from MarketConfigurator
        address acl = IMarketConfigurator(msg.sender).acl();
        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address treasury = IMarketConfigurator(msg.sender).treasury();

        // deploy pool
        address pool = _deployPool({
            marketConfigurator: msg.sender,
            underlying: underlying,
            contractsRegister: contractsRegister,
            acl: acl,
            treasury: treasury,
            interestRateModel: defaultInterestRateModel,
            name: name,
            symbol: symbol,
            _version: version
        });

        address poolQuotaKeeper =
            _deployPoolQuotaKeeper({marketConfigurator: msg.sender, pool: pool, _version: version});

        // Inflation attack protection
        if (IERC20(underlying).balanceOf(address(this)) < 1e5) revert InsufficientBalanceException();
        IERC20(underlying).forceApprove(pool, 1e5);
        IPoolV3(pool).deposit(1e5, address(0xdead));

        // TODO: rewrite with libraty which pack address list
        address[] memory accessList = new address[](2);
        accessList[0] = pool;
        accessList[1] = poolQuotaKeeper;

        return DeployResult({
            newContract: pool,
            accessList: accessList,
            onInstallOps: CallBuilder.build(_setPoolQuotaKeeper(pool, poolQuotaKeeper))
        });
    }

    function configure(address pool, bytes calldata callData) external view returns (Call[] memory calls) {
        // TODO: implement
    }

    //
    // MARKET HOOKS
    //

    // @dev Hook which is called when interest model is updated
    // @param pool - pool address
    // @param newModel - new interest model address
    // @return calls - array of calls to be executed
    function onUpdateInterestRateModel(address pool, address newModel)
        external
        view
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        calls = CallBuilder.build(_setInterestRateModel(pool, newModel));
    }

    /**
     * @notice Hook that executes when a creditManager is removed from the market.
     * It checks
     * @param _creditManager The address of the creditManager being removed.
     * @return calls An array of Call structs to be executed, setting the credit manager's debt limit to zero.
     */
    function onShutdownCreditSuite(address pool, address _creditManager)
        external
        view
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        if (IPoolV3(pool).creditManagerBorrowed(_creditManager) != 0) {
            revert CantRemoveNonEmptyCreditSuiteException(_creditManager);
        }

        calls = CallBuilder.build(_setCreditManagerDebtLimit(pool, _creditManager, 0));
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
        view
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        calls = CallBuilder.build(_setRateKeeper(IPoolV3(pool).poolQuotaKeeper(), rateKeeper));
    }

    function onShutdownMarket(address pool)
        external
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        // QUESTION: Why it was additinal statement `|| _creditManagers(pool).length != 0`
        if (IPoolV3(pool).totalBorrowed() != 0) {
            revert CantShutdownNonEmptyMarketException(pool);
        }

        calls = CallBuilder.build(
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
        override(IMarketHooks, MarketHookFactory)
        returns (Call[] memory calls)
    {
        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address priceOracle = IContractsRegister(contractsRegister).getPriceOracle(pool);
        // Check that underlying price is non-zero
        if (
            (IPriceOracleV3(priceOracle).getPrice(token) == 0)
                && (token == IPoolV3(pool).asset() || _quota(pool, token) != 0)
        ) revert IncorrectPriceException();
    }

    //
    // INTERNAL
    //
    function _deployPool(
        address marketConfigurator,
        address underlying,
        address contractsRegister,
        address acl,
        address treasury,
        address interestRateModel,
        string calldata name,
        string calldata symbol,
        uint256 _version
    ) internal returns (address pool) {
        bytes memory constructorParams =
            abi.encode(acl, contractsRegister, underlying, treasury, interestRateModel, uint256(0), name, symbol);
        bytes32 postfix = IBytecodeRepository(bytecodeRepository).getTokenSpecificPostfix(underlying);

        bytes32 salt = bytes32(bytes20(marketConfigurator));

        return IBytecodeRepository(bytecodeRepository).deployByDomain(
            DOMAIN_POOL, postfix, _version, constructorParams, salt
        );
    }

    function _deployPoolQuotaKeeper(address marketConfigurator, address pool, uint256 _version)
        internal
        returns (address pqk)
    {
        bytes memory constructorParams = abi.encode(pool);
        return IBytecodeRepository(bytecodeRepository).deploy(
            AP_POOL_QUOTA_KEEPER, _version, constructorParams, bytes32(bytes20(marketConfigurator))
        );
    }

    //
    // INTERNALS
    //
    function _quota(address pool, address token) internal view returns (uint96 quota) {
        (,,, quota,,) = IPoolQuotaKeeperV3(_quotaKeeper(pool)).getTokenQuotaParams(token);
    }

    function _quotaKeeper(address pool) internal view returns (address) {
        return IPoolV3(pool).poolQuotaKeeper();
    }

    //
    // CALL GENERATION

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
        call = Call({target: quotaKeeper, callData: abi.encodeCall(IPoolQuotaKeeperV3.setGauge, (newKeeper))});
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
