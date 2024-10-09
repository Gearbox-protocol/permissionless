// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IACLExt} from "../interfaces/extensions/IACLExt.sol";
import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";

import {
    IControllerTimelockV3, QueuedTransactionData, Policy, PolicyData
} from "../interfaces/IControllerTimelockV3.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {IPriceFeedStore} from "../interfaces/IPriceFeedStore.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IGaugeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IGaugeV3.sol";
import {ITumblerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ITumblerV3.sol";
import {IPriceOracleV3, PriceFeedParams} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {IPriceFeed} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IPriceFeed.sol";

import {AP_CONTROLLER_TIMELOCK, AP_PRICE_FEED_STORE} from "../libraries/ContractLiterals.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title Controller timelock V3
/// @notice Controller timelock is a governance contract that allows special actors less trusted than Gearbox Governance
///         to modify system parameters within set boundaries. This is mostly related to risk parameters that should be
///         adjusted frequently or periodic tasks (e.g., updating price feed limiters) that are too trivial to employ
///         the full governance for.
contract ControllerTimelockV3 is ACLTrait, IControllerTimelockV3 {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Contract type
    bytes32 public constant contractType = AP_CONTROLLER_TIMELOCK;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Map from function keys to respective policies
    mapping(string => Policy) public policies;

    /// @dev Whether the policy type is known by this contract. Set once in constructor.
    mapping(string => bool) internal _isValidPolicyKey;

    /// @notice List of all supported function keys
    string[13] public keys = [
        "setPriceFeed",
        "setMaxDebtPerBlockMultiplier",
        "forbidAdapter",
        "allowToken",
        "removeEmergencyLiquidator",
        "setCreditManagerDebtLimit",
        "setTotalDebtLimit",
        "setTokenLimit",
        "setTokenQuotaIncreaseFee",
        "setMinQuotaRate",
        "setMaxQuotaRate",
        "setTumblerQuotaRate",
        "updateTumblerRates"
    ];

    /// @notice Period before a mature transaction becomes stale
    uint256 public constant override GRACE_PERIOD = 14 days;

    /// @notice Default delay for controller policies
    uint40 public constant override DEFAULT_DELAY = 2 days;

    /// @notice Admin address that can cancel transactions
    address public override vetoAdmin;

    /// @notice Mapping from address to their status as executor
    EnumerableSet.AddressSet internal _executors;

    /// @notice Mapping from transaction hashes to their data
    mapping(bytes32 => QueuedTransactionData) public override queuedTransactions;

    /// @notice Address of the market configurator this CT corresponds to
    address public immutable marketConfigurator;

    /// @notice Constructor
    /// @param _acl Address of acl contract
    /// @param _vetoAdmin Admin that can cancel transactions
    constructor(address _acl, address _vetoAdmin, address _marketConfigurator) ACLTrait(_acl) {
        vetoAdmin = _vetoAdmin;
        marketConfigurator = _marketConfigurator;

        uint256 len = keys.length;
        unchecked {
            for (uint256 i; i < len; ++i) {
                policies[keys[i]].admin = IACLExt(_acl).getConfigurator();
                policies[keys[i]].delay = DEFAULT_DELAY;
                _isValidPolicyKey[keys[i]] = true;
            }
        }
    }

    // --------- //
    // MODIFIERS //
    // --------- //

    /// @dev Ensures that function caller is the veto admin
    modifier vetoAdminOnly() {
        _ensureVetoAdmin();
        _;
    }

    /// @dev Checks that the function is called by the correct policy admin
    modifier policyAdminOnly(string memory policyID) {
        _ensurePolicyAdmin(policyID);
        _;
    }

    /// @dev Reverts if the policy under the passed function key does not exist or the caller is not its admin
    function _ensurePolicyAdmin(string memory policyID) internal view {
        address admin = policies[policyID].admin;
        if (admin == address(0)) {
            revert PolicyDoesNotExistException();
        }

        if (msg.sender != admin) {
            revert CallerNotPolicyAdminException();
        }
    }

    /// @dev Reverts if `msg.sender` is not the veto admin
    function _ensureVetoAdmin() internal view {
        if (msg.sender != vetoAdmin) {
            revert CallerNotVetoAdminException();
        }
    }

    // -------- //
    // QUEUEING //
    // -------- //

    /// @notice Queues a transaction to change a price feed for a token
    function setPriceFeed(address pool, address token, address priceFeed)
        external
        override
        policyAdminOnly("setPriceFeed")
    {
        address priceFeedStore = IMarketConfigurator(marketConfigurator).priceFeedStore();
        address priceOracle = IMarketConfigurator(marketConfigurator).priceOracles(pool);

        _checkPriceFeed(priceFeedStore, pool, priceOracle, token, priceFeed);
        uint32 stalenessPeriod = IPriceFeedStore(priceFeedStore).getStalenessPeriod(priceFeed);

        _queueTransaction({
            policy: "setPriceFeed",
            target: priceOracle,
            signature: "setPriceFeed(address,address,uint32)",
            data: abi.encode(token, priceFeed, stalenessPeriod),
            sanityCheckCallData: abi.encodeCall(this.getCurrentPriceFeedHash, (priceOracle, token))
        });
    }

    /// @dev Performs validation on the price feed to disallow setting unknown price feeds and other dangerous actions
    function _checkPriceFeed(
        address priceFeedStore,
        address pool,
        address priceOracle,
        address token,
        address priceFeed
    ) internal view {
        if (
            !IPriceFeedStore(priceFeedStore).isAllowedPriceFeed(token, priceFeed)
                || IPriceOracleV3(priceOracle).priceFeeds(token) == address(0)
        ) {
            revert PriceFeedChecksFailedException();
        }

        (, int256 price,,,) = IPriceFeed(priceFeed).latestRoundData();
        address pqk = IPoolV3(pool).poolQuotaKeeper();
        (,,, uint96 quoted,,) = IPoolQuotaKeeperV3(pqk).getTokenQuotaParams(token);

        if (price == 0 && (token == IPoolV3(pool).asset() || quoted != 0)) revert PriceFeedChecksFailedException();
    }

    function getCurrentPriceFeedHash(address priceOracle, address token) public view returns (uint256) {
        PriceFeedParams memory pfParams = IPriceOracleV3(priceOracle).priceFeedParams(token);
        return uint256(keccak256(abi.encode(pfParams.priceFeed, pfParams.stalenessPeriod)));
    }

    /// @notice Queues a transaction to set a new max debt per block multiplier
    /// @param creditManager Adress of CM to update the multiplier for
    /// @param multiplier The new multiplier value
    function setMaxDebtPerBlockMultiplier(address creditManager, uint8 multiplier)
        external
        override
        policyAdminOnly("setMaxDebtPerBlockMultiplier")
    {
        _queueTransaction({
            policy: "setMaxDebtPerBlockMultiplier",
            target: ICreditManagerV3(creditManager).creditConfigurator(),
            signature: "setMaxDebtPerBlockMultiplier(uint8)",
            data: abi.encode(multiplier),
            sanityCheckCallData: abi.encodeCall(this.getMaxDebtPerBlockMultiplier, (creditManager))
        }); // U:[CT-3]
    }

    /// @dev Retrieves current max debt per block multiplier for a Credit Facade
    function getMaxDebtPerBlockMultiplier(address creditManager) public view returns (uint8) {
        return ICreditFacadeV3(ICreditManagerV3(creditManager).creditFacade()).maxDebtPerBlockMultiplier();
    }

    /// @notice Queues a transaction to forbid a third party contract adapter
    /// @param creditManager Adress of CM to forbid an adapter for
    /// @param adapter Address of adapter to forbid
    function forbidAdapter(address creditManager, address adapter) external override policyAdminOnly("forbidAdapter") {
        _queueTransaction({
            policy: "forbidAdapter",
            target: ICreditManagerV3(creditManager).creditConfigurator(),
            signature: "forbidAdapter(address)",
            data: abi.encode(adapter),
            sanityCheckCallData: ""
        }); // U: [CT-10]
    }

    /// @notice Queues a transaction to allow a previously forbidden token
    /// @param creditManager Adress of CM to allow a token for
    /// @param token Address of token to allow
    function allowToken(address creditManager, address token) external override policyAdminOnly("allowToken") {
        _queueTransaction({
            policy: "allowToken",
            target: ICreditManagerV3(creditManager).creditConfigurator(),
            signature: "allowToken(address)",
            data: abi.encode(token),
            sanityCheckCallData: ""
        });
    }

    /// @notice Queues a transaction to remove an emergency liquidator
    /// @param creditManager Adress of CM to remove an emergency liquidator from
    /// @param liquidator Liquidator address to remove
    function removeEmergencyLiquidator(address creditManager, address liquidator)
        external
        override
        policyAdminOnly("removeEmergencyLiquidator")
    {
        _queueTransaction({
            policy: "removeEmergencyLiquidator",
            target: ICreditManagerV3(creditManager).creditConfigurator(),
            signature: "removeEmergencyLiquidator(address)",
            data: abi.encode(liquidator),
            sanityCheckCallData: ""
        });
    }

    /// @notice Queues a transaction to set a new debt limit for a Credit Manager
    /// @param creditManager Adress of CM to update the debt limit for
    /// @param debtLimit The new debt limit
    function setCreditManagerDebtLimit(address creditManager, uint256 debtLimit)
        external
        override
        policyAdminOnly("setCreditManagerDebtLimit")
    {
        _queueTransaction({
            policy: "setCreditManagerDebtLimit",
            target: ICreditManagerV3(creditManager).pool(),
            signature: "setCreditManagerDebtLimit(address,uint256)",
            data: abi.encode(address(creditManager), debtLimit),
            sanityCheckCallData: abi.encodeCall(this.getCreditManagerDebtLimit, (creditManager))
        }); // U:[CT-5]
    }

    /// @dev Retrieves the current total debt limit for Credit Manager from its pool
    function getCreditManagerDebtLimit(address creditManager) public view returns (uint256) {
        address pool = ICreditManagerV3(creditManager).pool();
        return IPoolV3(pool).creditManagerDebtLimit(creditManager);
    }

    /// @notice Queues a transaction to set a new total debt limit for the entire pool
    /// @param pool Pool to update the limit for
    /// @param newLimit The new value of the limit
    function setTotalDebtLimit(address pool, uint256 newLimit) external override policyAdminOnly("setTotalDebtLimit") {
        _queueTransaction({
            policy: "setTotalDebtLimit",
            target: pool,
            signature: "setTotalDebtLimit(uint256)",
            data: abi.encode(newLimit),
            sanityCheckCallData: abi.encodeCall(this.getTotalDebtLimit, (pool))
        }); // U: [CT-13]
    }

    /// @dev Retrieves the total debt limit for a pool
    function getTotalDebtLimit(address pool) public view returns (uint256) {
        return IPoolV3(pool).totalDebtLimit();
    }

    /// @notice Queues a transaction to set a new limit on quotas for particular pool and token
    /// @param pool Pool to update the limit for
    /// @param token Token to update the limit for
    /// @param limit The new value of the limit
    function setTokenLimit(address pool, address token, uint96 limit)
        external
        override
        policyAdminOnly("setTokenLimit")
    {
        _queueTransaction({
            policy: "setTokenLimit",
            target: IPoolV3(pool).poolQuotaKeeper(),
            signature: "setTokenLimit(address,uint96)",
            data: abi.encode(token, limit),
            sanityCheckCallData: abi.encodeCall(this.getTokenLimit, (pool, token))
        }); // U: [CT-11]
    }

    /// @dev Retrieves the per-token quota limit from pool quota keeper
    function getTokenLimit(address pool, address token) public view returns (uint96) {
        address poolQuotaKeeper = IPoolV3(pool).poolQuotaKeeper();
        (,,,, uint96 oldLimit,) = IPoolQuotaKeeperV3(poolQuotaKeeper).getTokenQuotaParams(token);
        return oldLimit;
    }

    /// @notice Queues a transaction to set a new quota increase (trading) fee for a particular pool and token
    /// @param pool Pool to update the limit for
    /// @param token Token to update the limit for
    /// @param quotaIncreaseFee The new value of the fee in bp
    function setTokenQuotaIncreaseFee(address pool, address token, uint16 quotaIncreaseFee)
        external
        override
        policyAdminOnly("setTokenQuotaIncreaseFee")
    {
        _queueTransaction({
            policy: "setTokenQuotaIncreaseFee",
            target: IPoolV3(pool).poolQuotaKeeper(),
            signature: "setTokenQuotaIncreaseFee(address,uint16)",
            data: abi.encode(token, quotaIncreaseFee),
            sanityCheckCallData: abi.encodeCall(this.getTokenQuotaIncreaseFee, (pool, token))
        }); // U: [CT-12]
    }

    /// @dev Retrieves the quota increase fee for a token
    function getTokenQuotaIncreaseFee(address pool, address token) public view returns (uint16) {
        address poolQuotaKeeper = IPoolV3(pool).poolQuotaKeeper();
        (,, uint16 quotaIncreaseFee,,,) = IPoolQuotaKeeperV3(poolQuotaKeeper).getTokenQuotaParams(token);
        return quotaIncreaseFee;
    }

    /// @notice Queues a transaction to set a new minimal quota interest rate for particular pool and token
    /// @param pool Pool to update the rate for
    /// @param token Token to set the minimal rate for
    /// @param rate The new minimal rate
    function setMinQuotaRate(address pool, address token, uint16 rate)
        external
        override
        policyAdminOnly("setMinQuotaRate")
    {
        _queueTransaction({
            policy: "setMinQuotaRate",
            target: IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge(),
            signature: "changeQuotaMinRate(address,uint16)",
            data: abi.encode(token, rate),
            sanityCheckCallData: abi.encodeCall(this.getMinQuotaRate, (pool, token))
        }); // U: [CT-15A]
    }

    /// @dev Retrieves the current minimal quota rate for a token in a gauge
    function getMinQuotaRate(address pool, address token) public view returns (uint16) {
        address gauge = IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge();
        (uint16 minRate,,,) = IGaugeV3(gauge).quotaRateParams(token);
        return minRate;
    }

    /// @notice Queues a transaction to set a new maximal quota interest rate for particular pool and token
    /// @dev Requires the policy for keccak(group(pool), group(token), "TOKEN_QUOTA_MAX_RATE") to be enabled,
    ///      otherwise auto-fails the check
    /// @param pool Pool to update the rate for
    /// @param token Token to set the maximal rate for
    /// @param rate The new maximal rate
    function setMaxQuotaRate(address pool, address token, uint16 rate)
        external
        override
        policyAdminOnly("setMaxQuotaRate")
    {
        _queueTransaction({
            policy: "setMaxQuotaRate",
            target: IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge(),
            signature: "changeQuotaMaxRate(address,uint16)",
            data: abi.encode(token, rate),
            sanityCheckCallData: abi.encodeCall(this.getMaxQuotaRate, (pool, token))
        }); // U: [CT-15B]
    }

    /// @dev Retrieves the current maximal quota rate for a token in a gauge
    function getMaxQuotaRate(address pool, address token) public view returns (uint16) {
        address gauge = IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge();
        (, uint16 maxRate,,) = IGaugeV3(gauge).quotaRateParams(token);
        return maxRate;
    }

    /// @notice Queues a transaction to set a new quota interest rate in a Tumbler
    /// @notice Requires the PQK to have a Tumbler set as its gauge, otherwise will revert
    /// @param pool Pool to update the rate
    /// @param token Token to set the new rate
    /// @param rate The new rate
    function setTumblerQuotaRate(address pool, address token, uint16 rate)
        external
        override
        policyAdminOnly("setTumblerQuotaRate")
    {
        _queueTransaction({
            policy: "setTumblerQuotaRate",
            target: IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge(),
            signature: "setRate(address,uint16)",
            data: abi.encode(token, rate),
            sanityCheckCallData: abi.encodeCall(this.getTumblerRate, (pool, token))
        });
    }

    /// @dev Retrieves the current quota rate for a token in a Tumbler
    function getTumblerRate(address pool, address token) public view returns (uint16) {
        address tumbler = IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge();

        address[] memory tokens = new address[](1);
        tokens[0] = token;

        uint16[] memory rates = ITumblerV3(tumbler).getRates(tokens);

        return rates[0];
    }

    /// @notice Queues a transaction to update rates in a Tumbler
    /// @notice Requires the PQK to have a Tumbler set as its gauge, otherwise will revert
    /// @param pool Pool to update rates for
    function updateTumblerRates(address pool) external override policyAdminOnly("updateTumblerRates") {
        _queueTransaction({
            policy: "updateTumblerRates",
            target: IPoolQuotaKeeperV3(IPoolV3(pool).poolQuotaKeeper()).gauge(),
            signature: "updateRates()",
            data: "",
            sanityCheckCallData: ""
        });
    }

    /// @dev Internal function that stores the transaction in the queued tx map
    /// @param target The contract to call
    /// @param signature The signature of the called function
    /// @param data The call data
    /// @return Hash of the queued transaction
    function _queueTransaction(
        string memory policy,
        address target,
        string memory signature,
        bytes memory data,
        bytes memory sanityCheckCallData
    ) internal returns (bytes32) {
        uint256 eta = block.timestamp + policies[policy].delay;

        bytes32 txHash = keccak256(abi.encode(msg.sender, target, signature, data));
        uint256 sanityCheckValue;

        if (sanityCheckCallData.length != 0) {
            (, bytes memory returndata) = address(this).staticcall(sanityCheckCallData);
            sanityCheckValue = abi.decode(returndata, (uint256));
        }

        queuedTransactions[txHash] = QueuedTransactionData({
            queued: true,
            initiator: msg.sender,
            target: target,
            eta: uint40(eta),
            signature: signature,
            data: data,
            sanityCheckValue: sanityCheckValue,
            sanityCheckCallData: sanityCheckCallData
        });

        emit QueueTransaction({
            txHash: txHash,
            initiator: msg.sender,
            target: target,
            signature: signature,
            data: data,
            eta: uint40(eta)
        });

        return txHash;
    }

    // --------- //
    // EXECUTION //
    // --------- //

    /// @notice Sets the transaction's queued status as false, effectively cancelling it
    /// @param txHash Hash of the transaction to be cancelled
    function cancelTransaction(bytes32 txHash)
        external
        override
        vetoAdminOnly // U: [CT-7]
    {
        queuedTransactions[txHash].queued = false;
        emit CancelTransaction(txHash);
    }

    /// @notice Executes a queued transaction
    /// @param txHash Hash of the transaction to be executed
    function executeTransaction(bytes32 txHash) external override {
        QueuedTransactionData memory qtd = queuedTransactions[txHash];

        if (!qtd.queued) {
            revert TxNotQueuedException(); // U: [CT-7]
        }

        if (msg.sender != qtd.initiator && !_executors.contains(msg.sender)) {
            revert CallerNotExecutorException(); // U: [CT-9]
        }

        address target = qtd.target;
        uint40 eta = qtd.eta;
        string memory signature = qtd.signature;
        bytes memory data = qtd.data;

        if (block.timestamp < eta || block.timestamp > eta + GRACE_PERIOD) {
            revert TxExecutedOutsideTimeWindowException(); // U: [CT-9]
        }

        // In order to ensure that we do not accidentally override a change
        // made by configurator or another admin, the current value of the parameter
        // is compared to the value at the moment of tx being queued
        if (qtd.sanityCheckCallData.length != 0) {
            (, bytes memory returndata) = address(this).staticcall(qtd.sanityCheckCallData);

            if (abi.decode(returndata, (uint256)) != qtd.sanityCheckValue) {
                revert ParameterChangedAfterQueuedTxException();
            }
        }

        queuedTransactions[txHash].queued = false;

        bytes memory callData;

        if (bytes(signature).length == 0) {
            callData = data;
        } else {
            callData = abi.encodePacked(bytes4(keccak256(bytes(signature))), data);
        }

        (bool success,) = target.call(callData);

        if (!success) {
            revert TxExecutionRevertedException(); // U: [CT-9]
        }

        emit ExecuteTransaction(txHash); // U: [CT-9]
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    /// @notice Sets a new veto admin address
    function setVetoAdmin(address newAdmin)
        external
        override
        configuratorOnly // U: [CT-8]
    {
        if (vetoAdmin != newAdmin) {
            vetoAdmin = newAdmin; // U: [CT-8]
            emit SetVetoAdmin(newAdmin); // U: [CT-8]
        }
    }

    /// @notice Adds an address as an executor
    function addExecutor(address executorAddress) external override configuratorOnly {
        if (!_executors.contains(executorAddress)) {
            _executors.add(executorAddress);
            emit AddExecutor(executorAddress);
        }
    }

    /// @notice Removes an address as an executor
    function removeExecutor(address executorAddress) external override configuratorOnly {
        if (_executors.contains(executorAddress)) {
            _executors.remove(executorAddress);
            emit RemoveExecutor(executorAddress);
        }
    }

    /// @notice Returns whether an address is an executor
    function isExecutor(address addr) external view override returns (bool) {
        return _executors.contains(addr);
    }

    /// @notice Returns the list of all executors
    function executors() external view override returns (address[] memory) {
        return _executors.values();
    }

    function setPolicyAdmin(string memory policyID, address newAdmin) external configuratorOnly {
        if (!_isValidPolicyKey[policyID]) revert InvalidPolicyException();

        if (policies[policyID].admin != newAdmin) {
            policies[policyID].admin = newAdmin;
            emit SetPolicyAdmin(policyID, newAdmin);
        }
    }

    function setPolicyDelay(string memory policyID, uint40 newDelay) external configuratorOnly {
        if (!_isValidPolicyKey[policyID]) revert InvalidPolicyException();

        if (policies[policyID].delay != newDelay) {
            policies[policyID].delay = newDelay;
            emit SetPolicyDelay(policyID, newDelay);
        }
    }

    function policyState() external view returns (PolicyData[] memory pData) {
        uint256 len = keys.length;

        unchecked {
            for (uint256 i; i < len; ++i) {
                string memory id = keys[i];
                Policy storage p = policies[id];
                pData[i].id = id;
                pData[i].admin = p.admin;
                pData[i].delay = p.delay;
            }
        }
    }
}
