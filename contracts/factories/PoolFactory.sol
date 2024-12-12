// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {SafeERC20} from "@1inch/solidity-utils/contracts/libraries/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IPriceFeed} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IPriceFeed.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {InsufficientBalanceException} from "@gearbox-protocol/core-v3/contracts/interfaces/IExceptions.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {IFactory} from "../interfaces/factories/IFactory.sol";
import {IMarketFactory} from "../interfaces/factories/IMarketFactory.sol";
import {IPoolFactory} from "../interfaces/factories/IPoolFactory.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {Call, DeployResult} from "../interfaces/Types.sol";

import {CallBuilder} from "../libraries/CallBuilder.sol";
import {
    AP_DEFAULT_IRM,
    AP_POOL_FACTORY,
    AP_POOL_QUOTA_KEEPER,
    DOMAIN_POOL,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";

import {AbstractFactory} from "./AbstractFactory.sol";
import {AbstractMarketFactory} from "./AbstractMarketFactory.sol";

contract PoolFactory is AbstractMarketFactory, IPoolFactory {
    using SafeERC20 for IERC20;
    using CallBuilder for Call;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_POOL_FACTORY;

    /// @notice Address of the default IRM
    address public immutable defaultInterestRateModel;

    /// @notice Thrown when trying to shutdown a credit suite with non-zero outstanding debt
    error CantShutdownNonEmptyCreditSuiteException(address creditManager);

    /// @notice Thrown when attempting to shutdown a market with non-zero outstanding debt
    error CantShutdownNonEmptyMarketException(address pool);

    /// @notice Constructor
    /// @param addressProvider_ Address provider contract address
    constructor(address addressProvider_) AbstractFactory(addressProvider_) {
        defaultInterestRateModel = _getContract(AP_DEFAULT_IRM, NO_VERSION_CONTROL);
    }

    // ---------- //
    // DEPLOYMENT //
    // ---------- //

    function deployPool(address underlying, string calldata name, string calldata symbol)
        external
        override
        onlyMarketConfigurators
        returns (DeployResult memory)
    {
        address acl = IMarketConfigurator(msg.sender).acl();
        address contractsRegister = IMarketConfigurator(msg.sender).contractsRegister();
        address treasury = IMarketConfigurator(msg.sender).treasury();

        address pool = _deployPool({
            marketConfigurator: msg.sender,
            underlying: underlying,
            contractsRegister: contractsRegister,
            acl: acl,
            treasury: treasury,
            interestRateModel: defaultInterestRateModel,
            name: name,
            symbol: symbol
        });

        address quotaKeeper = _deployQuotaKeeper({marketConfigurator: msg.sender, pool: pool});

        // Inflation attack protection
        // FIXME: unless executed as part of the batch, this can be stolen by someone else to create their market
        if (IERC20(underlying).balanceOf(address(this)) < 1e5) revert InsufficientBalanceException();
        IERC20(underlying).forceApprove(pool, 1e5);
        IPoolV3(pool).deposit(1e5, address(0xdead));

        return DeployResult({
            newContract: pool,
            onInstallOps: CallBuilder.build(
                _addToAccessList(msg.sender, pool),
                _addToAccessList(msg.sender, quotaKeeper),
                _setQuotaKeeper(pool, quotaKeeper)
            )
        });
    }

    // ------------ //
    // MARKET HOOKS //
    // ------------ //

    function onCreateMarket(address pool, address, address interestRateModel, address rateKeeper, address, address)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory calls)
    {
        calls = CallBuilder.build(
            _setInterestRateModel(pool, interestRateModel), _setRateKeeper(_quotaKeeper(pool), rateKeeper)
        );
    }

    function onShutdownMarket(address pool)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory calls)
    {
        if (IPoolV3(pool).totalBorrowed() != 0) {
            revert CantShutdownNonEmptyMarketException(pool);
        }

        calls = CallBuilder.build(_setTotalDebtLimit(pool, 0), _setWithdrawFee(pool, 0));
    }

    function onCreateCreditSuite(address pool, address creditManager)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        return CallBuilder.build(
            _setCreditManagerDebtLimit(pool, creditManager, 0), _addCreditManager(_quotaKeeper(pool), creditManager)
        );
    }

    function onShutdownCreditSuite(address creditManager)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        address pool = ICreditManagerV3(creditManager).pool();

        if (IPoolV3(pool).creditManagerBorrowed(creditManager) != 0) {
            revert CantShutdownNonEmptyCreditSuiteException(creditManager);
        }

        return CallBuilder.build(_setCreditManagerDebtLimit(pool, creditManager, 0));
    }

    function onUpdateInterestRateModel(address pool, address newInterestRateModel, address)
        external
        pure
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        return CallBuilder.build(_setInterestRateModel(pool, newInterestRateModel));
    }

    function onUpdateRateKeeper(address pool, address newRateKeeper, address)
        external
        view
        override(AbstractMarketFactory, IMarketFactory)
        returns (Call[] memory)
    {
        return CallBuilder.build(_setRateKeeper(_quotaKeeper(pool), newRateKeeper));
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function configure(address pool, bytes calldata callData)
        external
        view
        override(AbstractFactory, IFactory)
        returns (Call[] memory)
    {
        bytes4 selector = bytes4(callData);
        if (
            selector == IPoolV3.setTotalDebtLimit.selector || selector == IPoolV3.setCreditManagerDebtLimit.selector
                || selector == IPoolV3.setWithdrawFee.selector
        ) {
            return CallBuilder.build(Call({target: pool, callData: callData}));
        } else if (
            selector == IPoolQuotaKeeperV3.setTokenLimit.selector
                || selector == IPoolQuotaKeeperV3.setTokenQuotaIncreaseFee.selector
        ) {
            // QUESTION: is it safe to set non-zero limit to tokens with zero price? can it break things?
            return CallBuilder.build(Call({target: _quotaKeeper(pool), callData: callData}));
        } else {
            revert ForbiddenConfigurationCallException(selector);
        }
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _deployPool(
        address marketConfigurator,
        address underlying,
        address contractsRegister,
        address acl,
        address treasury,
        address interestRateModel,
        string calldata name,
        string calldata symbol
    ) internal returns (address) {
        bytes32 postfix = _getTokenSpecificPostfix(underlying);
        bytes memory constructorParams =
            abi.encode(acl, contractsRegister, underlying, treasury, interestRateModel, uint256(0), name, symbol);
        bytes32 salt = bytes32(bytes20(marketConfigurator));
        return _deployByDomain({
            domain: DOMAIN_POOL,
            postfix: postfix,
            version: version,
            constructorParams: constructorParams,
            salt: salt
        });
    }

    function _deployQuotaKeeper(address marketConfigurator, address pool) internal returns (address) {
        return _deploy({
            contractType: AP_POOL_QUOTA_KEEPER,
            version: version,
            constructorParams: abi.encode(pool),
            salt: bytes32(bytes20(marketConfigurator))
        });
    }

    function _setQuotaKeeper(address pool, address quotaKeeper) internal pure returns (Call memory) {
        return Call({target: pool, callData: abi.encodeCall(IPoolV3.setPoolQuotaKeeper, quotaKeeper)});
    }

    function _setRateKeeper(address quotaKeeper, address rateKeeper) internal pure returns (Call memory) {
        return Call({target: quotaKeeper, callData: abi.encodeCall(IPoolQuotaKeeperV3.setGauge, (rateKeeper))});
    }

    function _setInterestRateModel(address pool, address interestRateModel) internal pure returns (Call memory) {
        return Call({target: pool, callData: abi.encodeCall(IPoolV3.setInterestRateModel, (interestRateModel))});
    }

    function _setTotalDebtLimit(address pool, uint256 limit) internal pure returns (Call memory) {
        return Call({target: pool, callData: abi.encodeCall(IPoolV3.setTotalDebtLimit, (limit))});
    }

    function _setCreditManagerDebtLimit(address pool, address creditManager, uint256 limit)
        internal
        pure
        returns (Call memory)
    {
        return Call({target: pool, callData: abi.encodeCall(IPoolV3.setCreditManagerDebtLimit, (creditManager, limit))});
    }

    function _setWithdrawFee(address pool, uint256 fee) internal pure returns (Call memory) {
        return Call({target: pool, callData: abi.encodeCall(IPoolV3.setWithdrawFee, (fee))});
    }

    function _addCreditManager(address quotaKeeper, address creditManager) internal pure returns (Call memory) {
        return
            Call({target: quotaKeeper, callData: abi.encodeCall(IPoolQuotaKeeperV3.addCreditManager, (creditManager))});
    }
}
