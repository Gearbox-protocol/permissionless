// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";

enum PolicyType {
    None,
    UintRange,
    AddressInSet,
    NoValueCheck
}

struct Policy {
    address admin;
    uint40 delay;
    PolicyType policyType;
}

struct UintRange {
    uint256 minValue;
    uint256 maxValue;
}

struct QueuedTransactionData {
    bool queued;
    address initiator;
    address target;
    uint40 eta;
    string signature;
    bytes data;
    uint256 sanityCheckValue;
    bytes sanityCheckCallData;
}

struct PolicyUintRange {
    string id;
    address admin;
    uint40 delay;
    uint256 minValue;
    uint256 maxValue;
}

struct AddressSet {
    address key;
    address[] values;
}

struct PolicyAddressSet {
    string id;
    address admin;
    uint40 delay;
    AddressSet[] addressSet;
}

struct PolicyNoCheck {
    string id;
    address admin;
    uint40 delay;
}

struct PolicyState {
    PolicyUintRange[] policiesInRange;
    PolicyAddressSet[] policiesAddressSet;
    PolicyNoCheck[] policiesNoValueCheck;
}

interface IControllerTimelockV3Events {
    /// @notice Emitted when the veto admin of the controller is updated
    event SetVetoAdmin(address indexed admin);

    /// @notice Emitted when an address' status as executor is changed
    event AddExecutor(address indexed executor);

    /// @notice Emitted when an address' status as executor is changed
    event RemoveExecutor(address indexed executor);

    /// @notice Emitted when a transaction is queued
    event QueueTransaction(
        bytes32 indexed txHash, address indexed initiator, address target, string signature, bytes data, uint40 eta
    );

    /// @notice Emitted when a transaction is executed
    event ExecuteTransaction(bytes32 indexed txHash);

    /// @notice Emitted when a transaction is cancelled
    event CancelTransaction(bytes32 indexed txHash);

    event SetPolicyRange(string policyID, uint256 min, uint256 max);

    event AddAddressToPolicySet(string policyID, address key, address value);

    event RemoveAddressFromPolicySet(string policyID, address key, address value);

    event SetPolicyAdmin(string policyId, address newAdmin);

    event SetPolicyDelay(string policyId, uint40 newDelay);
}

interface IControllerTimelockV3Exceptions {
    /// @notice Thrown when the new parameter values do not satisfy required conditions
    error ParameterChecksFailedException();

    /// @notice Thrown when attempting to execute a non-queued transaction
    error TxNotQueuedException();

    /// @notice Thrown when attempting to execute a transaction that is either immature or stale
    error TxExecutedOutsideTimeWindowException();

    /// @notice Thrown when execution of a transaction fails
    error TxExecutionRevertedException();

    /// @notice Thrown when the value of a parameter on execution is different from the value on queue
    error ParameterChangedAfterQueuedTxException();

    /// @notice Thrown when an address that is not the designated executor attempts to execute a transaction
    error CallerNotExecutorException();

    /// @notice Thrown on attempting to call an access restricted function not as veto admin
    error CallerNotVetoAdminException();

    /// @notice Thrown when the policy for the called function is not set
    error PolicyDoesNotExistException();

    /// @notice Thrown when the caller is not the policy admin
    error CallerNotPolicyAdminException();

    /// @notice Thrown when the new value is not in the range defined by policy
    error UintIsNotInRangeException(uint256, uint256);

    /// @notice Thrown when the address is not in the set defined by policy
    error AddressIsNotInSetException(address[]);

    /// @notice Thrown when attempting to enable a policy that is not known to the controller
    error InvalidPolicyException();
}

/// @title Controller timelock V3 interface
interface IControllerTimelockV3 is IControllerTimelockV3Events, IControllerTimelockV3Exceptions, IVersion {
    // -------- //
    // QUEUEING //
    // -------- //

    function setMaxDebtPerBlockMultiplier(address creditManager, uint8 multiplier) external;

    function setDebtLimits(address creditManager, uint128 minDebt, uint128 maxDebt) external;

    function setCreditManagerDebtLimit(address creditManager, uint256 debtLimit) external;

    function rampLiquidationThreshold(
        address creditManager,
        address token,
        uint16 liquidationThresholdFinal,
        uint40 rampStart,
        uint24 rampDuration
    ) external;

    function forbidAdapter(address creditManager, address adapter) external;

    function setTotalDebtLimit(address pool, uint256 newLimit) external;

    function setTokenLimit(address pool, address token, uint96 limit) external;

    function setTokenQuotaIncreaseFee(address pool, address token, uint16 quotaIncreaseFee) external;

    function setMinQuotaRate(address pool, address token, uint16 rate) external;

    function setMaxQuotaRate(address pool, address token, uint16 rate) external;

    function setLPPriceFeedLimiter(address priceFeed, uint256 lowerBound) external;

    function setPriceFeed(address priceOracle, address token, address priceFeed, uint32 stalenessPeriod) external;

    function removeEmergencyLiquidator(address creditManager, address liquidator) external;

    function allowToken(address creditManager, address token) external;

    function setLiquidationThreshold(address creditManager, address token, uint16 liquidationThreshold) external;

    function setTumblerQuotaRate(address pool, address token, uint16 rate) external;

    function updateTumblerRates(address pool) external;

    // --------- //
    // EXECUTION //
    // --------- //

    function GRACE_PERIOD() external view returns (uint256);

    function DEFAULT_DELAY() external view returns (uint40);

    function queuedTransactions(bytes32 txHash)
        external
        view
        returns (
            bool queued,
            address initiator,
            address target,
            uint40 eta,
            string memory signature,
            bytes memory data,
            uint256 sanityCheckValue,
            bytes memory sanityCheckCallData
        );

    function executeTransaction(bytes32 txHash) external;

    function cancelTransaction(bytes32 txHash) external;

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function vetoAdmin() external view returns (address);

    function isExecutor(address addr) external view returns (bool);

    function setVetoAdmin(address newAdmin) external;

    function addExecutor(address executorAddress) external;

    function removeExecutor(address executorAddress) external;

    function executors() external view returns (address[] memory);
}
