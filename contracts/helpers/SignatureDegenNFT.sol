// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {IDegenNFT} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IDegenNFT.sol";

import {IContractsRegister} from "../interfaces/IContractsRegister.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/// @title Signature degen NFT
/// @notice Degen NFT that gates credit account opening via EIP-712 approvals from Gearbox and curator signers
/// @dev Instead of ERC-721 balances, stores per-(accountOwner, creditManager) opening deadlines that the credit
///      facade consumes via `burn` when opening an account
contract SignatureDegenNFT is EIP712, IDegenNFT {
    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = "DEGEN_NFT::DEFAULT";

    /// @notice EIP-712 typehash for mint / opening approvals
    bytes32 public constant MINT_TYPEHASH =
        keccak256("Mint(address creditManager,address accountOwner,uint32 deadline)");

    /// @notice Market configurator this degen NFT is bound to
    address public immutable marketConfigurator;

    /// @notice Contracts register of the market configurator
    address public immutable contractsRegister;

    /// @notice Authorized Gearbox signer for opening approvals
    address public immutable gearboxSigner;

    /// @notice Authorized curator signer for opening approvals
    address public immutable curatorSigner;

    /// @notice Opening deadline for `accountOwner` on `creditManager`, or 0 if none / already consumed
    mapping(address accountOwner => mapping(address creditManager => uint32 deadline)) public openingDeadlines;

    /// @notice Emitted when an opening is approved for `accountOwner` on `creditManager` until `deadline`
    event ApproveOpening(address indexed accountOwner, address indexed creditManager, uint32 deadline);

    /// @notice Emitted when an opening approval for `accountOwner` on `creditManager` is consumed
    event Burn(address indexed accountOwner, address indexed creditManager);

    /// @notice Thrown when the Gearbox signature does not recover to `gearboxSigner`
    error InvalidGearboxSignatureException();

    /// @notice Thrown when the curator signature does not recover to `curatorSigner`
    error InvalidCuratorSignatureException();

    /// @notice Thrown when the caller is neither a valid credit facade nor the emergency admin
    error CallerIsNotCreditFacadeOrEmergencyAdminException(address caller);

    /// @notice Thrown when there is no valid (non-expired) opening approval to consume
    error CannotOpenException();

    /// @notice Thrown when decoded signature params do not match the burn call context
    error InvalidSignatureParamsException();

    /// @dev Ensures the caller is a registered credit facade or the market emergency admin
    modifier onlyCreditFacadeOrEmergencyAdmin() {
        _ensureCallerIsCreditFacadeOrEmergencyAdmin();
        _;
    }

    /// @notice Constructor
    /// @param marketConfigurator_ Market configurator address
    /// @param gearboxSigner_ Authorized Gearbox signer
    /// @param curatorSigner_ Authorized curator signer
    constructor(address marketConfigurator_, address gearboxSigner_, address curatorSigner_)
        EIP712("SignatureDegenNFT", "1")
    {
        marketConfigurator = marketConfigurator_;
        contractsRegister = IMarketConfigurator(marketConfigurator_).contractsRegister();
        gearboxSigner = gearboxSigner_;
        curatorSigner = curatorSigner_;
    }

    /// @notice Serialized contract state
    function serialize() external view override returns (bytes memory) {
        return abi.encode(marketConfigurator, contractsRegister, gearboxSigner, curatorSigner);
    }

    /// @notice Consumes a previously recorded opening approval for `onBehalfOf`
    /// @dev Credit manager is inferred from the calling credit facade
    /// @param onBehalfOf Account owner whose approval is consumed
    function burn(address onBehalfOf, uint256) external onlyCreditFacadeOrEmergencyAdmin {
        address creditManager = ICreditFacadeV3(msg.sender).creditManager();
        _burn(onBehalfOf, creditManager);
    }

    /// @notice Approves and immediately consumes an opening using EIP-712 signatures
    /// @dev Credit manager in `signatureData` must match the calling credit facade's credit manager
    /// @param onBehalfOf Account owner; must match `accountOwner` in `signatureData`
    /// @param signatureData ABI-encoded `(creditManager, accountOwner, deadline, gearboxSignature, curatorSignature)`
    function burn(address onBehalfOf, uint256, bytes calldata signatureData)
        external
        onlyCreditFacadeOrEmergencyAdmin
    {
        (
            address creditManager,
            address accountOwner,
            uint32 deadline,
            bytes memory gearboxSignature,
            bytes memory curatorSignature
        ) = abi.decode(signatureData, (address, address, uint32, bytes, bytes));

        if (accountOwner != onBehalfOf || creditManager != ICreditFacadeV3(msg.sender).creditManager()) {
            revert InvalidSignatureParamsException();
        }

        _approveOpening(accountOwner, creditManager, deadline, gearboxSignature, curatorSignature);
        _burn(accountOwner, creditManager);
    }

    /// @notice Records an opening approval if both EIP-712 signatures are valid
    /// @param creditManager Credit manager the approval is for
    /// @param accountOwner Account owner the approval is for
    /// @param deadline Timestamp until which the approval is valid
    /// @param gearboxSignature EIP-712 signature from `gearboxSigner`
    /// @param curatorSignature EIP-712 signature from `curatorSigner`
    function approveOpening(
        address creditManager,
        address accountOwner,
        uint32 deadline,
        bytes calldata gearboxSignature,
        bytes calldata curatorSignature
    ) external {
        _approveOpening(accountOwner, creditManager, deadline, gearboxSignature, curatorSignature);
    }

    /// @dev Consumes the opening approval for `accountOwner` on `creditManager`
    /// @dev Reverts if the approval is missing or expired
    function _burn(address accountOwner, address creditManager) internal {
        if (block.timestamp > openingDeadlines[accountOwner][creditManager]) revert CannotOpenException();
        openingDeadlines[accountOwner][creditManager] = 0;

        emit Burn(accountOwner, creditManager);
    }

    /// @dev Validates both signatures and stores the opening deadline
    function _approveOpening(
        address accountOwner,
        address creditManager,
        uint32 deadline,
        bytes memory gearboxSignature,
        bytes memory curatorSignature
    ) internal {
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(MINT_TYPEHASH, creditManager, accountOwner, deadline)));

        if (ECDSA.recover(digest, gearboxSignature) != gearboxSigner) revert InvalidGearboxSignatureException();
        if (ECDSA.recover(digest, curatorSignature) != curatorSigner) revert InvalidCuratorSignatureException();

        openingDeadlines[accountOwner][creditManager] = deadline;

        emit ApproveOpening(accountOwner, creditManager, deadline);
    }

    /// @dev Reverts unless caller is the emergency admin or a credit facade of a registered credit manager
    function _ensureCallerIsCreditFacadeOrEmergencyAdmin() internal view {
        if (msg.sender != IMarketConfigurator(marketConfigurator).emergencyAdmin() && !_callerIsCreditFacade()) {
            revert CallerIsNotCreditFacadeOrEmergencyAdminException(msg.sender);
        }
    }

    /// @dev Returns whether `msg.sender` is the credit facade of a registered credit manager
    function _callerIsCreditFacade() internal view returns (bool) {
        address creditManager = ICreditFacadeV3(msg.sender).creditManager();
        if (
            ICreditManagerV3(creditManager).creditFacade() != msg.sender
                || !IContractsRegister(contractsRegister).isCreditManager(creditManager)
        ) return false;

        return true;
    }
}
