// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {IDegenNFT} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IDegenNFT.sol";

import {IACL} from "../interfaces/IACL.sol";
import {IContractsRegister} from "../interfaces/IContractsRegister.sol";
import {IMarketConfigurator} from "../interfaces/IMarketConfigurator.sol";
import {ROLE_OPENING_SIGNER} from "../libraries/ContractLiterals.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

struct OpeningSignature {
    address creditManager;
    address accountOwner;
    uint32 deadline;
    uint32 nonce;
    bytes signature;
}

struct OpeningInfo {
    uint32 deadline;
    uint32 nonce;
}

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
        keccak256("Mint(address creditManager,address accountOwner,uint32 deadline,uint32 nonce)");

    /// @notice Market ACL contract
    address public immutable acl;

    /// @notice Market configurator this degen NFT is bound to
    address public immutable marketConfigurator;

    /// @notice Contracts register of the market configurator
    address public immutable contractsRegister;

    /// @notice Minimum number of signatures required to approve an opening
    uint16 public immutable minSignaturesRequired;

    /// @notice Next Degen NFT to burn (optional)
    address public immutable nextDegenNFT;

    /// @notice Opening deadline and nonce for `accountOwner` on `creditManager`
    mapping(address accountOwner => mapping(address creditManager => OpeningInfo)) public openingDeadlines;

    /// @notice Emitted when an opening is approved for `accountOwner` on `creditManager` until `deadline`
    event ApproveOpening(address indexed accountOwner, address indexed creditManager, uint32 deadline);

    /// @notice Emitted when an opening approval for `accountOwner` on `creditManager` is consumed
    event Burn(address indexed accountOwner, address indexed creditManager);

    /// @notice Thrown when the number of signers is less than the `minSignaturesRequired`
    error NotEnoughSignersException();

    /// @notice Thrown when one of the opening parameter structs does not match the others
    error OpeningParamsMismatchException();

    /// @notice Thrown when the caller is neither a valid credit facade nor the emergency admin
    error CallerIsNotCreditFacadeOrEmergencyAdminException(address caller);

    /// @notice Thrown when there is no valid (non-expired) opening approval to consume
    error CannotOpenException();

    /// @notice Thrown when decoded signature params do not match the burn call context
    error InvalidSignatureParamsException();

    /// @notice Thrown when the next signer in the array has an address no larger than the previous one
    error IncorrectSignerSortingException();

    /// @notice Thrown when an opening signature struct has an incorrect nonce
    error IncorrectNonceException();

    /// @dev Ensures the caller is a registered credit facade or the market emergency admin
    modifier onlyCreditFacadeOrEmergencyAdmin() {
        _ensureCallerIsCreditFacadeOrEmergencyAdmin();
        _;
    }

    /// @notice Constructor
    /// @param marketConfigurator_ Market configurator address
    constructor(address marketConfigurator_, uint16 _minSignaturesRequired, address _nextDegenNFT)
        EIP712("SignatureDegenNFT", "3_10")
    {
        marketConfigurator = marketConfigurator_;
        contractsRegister = IMarketConfigurator(marketConfigurator_).contractsRegister();
        acl = IMarketConfigurator(marketConfigurator_).acl();
        minSignaturesRequired = _minSignaturesRequired;
        nextDegenNFT = _nextDegenNFT;
    }

    /// @notice Serialized contract state
    function serialize() external view override returns (bytes memory) {
        return abi.encode(marketConfigurator, contractsRegister, minSignaturesRequired, nextDegenNFT);
    }

    /// @notice Consumes a previously recorded opening approval for `onBehalfOf`
    /// @dev Credit manager is inferred from the calling credit facade
    /// @param onBehalfOf Account owner whose approval is consumed
    function burn(address onBehalfOf, uint256) external onlyCreditFacadeOrEmergencyAdmin {
        address creditManager = ICreditFacadeV3(msg.sender).creditManager();
        _burn(onBehalfOf, creditManager);
    }

    /// @notice Approves and immediately consumes an opening using EIP-712 signatures
    /// @dev The first credit manager in `openingSignaturesEncoded` must match the calling credit facade's credit manager
    /// @param onBehalfOf Account owner; must match the first `accountOwner` in `openingSignaturesEncoded`
    /// @param openingSignaturesEncoded ABI-encoded array of OpeningSignature structs
    function burn(address onBehalfOf, uint256, bytes calldata openingSignaturesEncoded)
        external
        onlyCreditFacadeOrEmergencyAdmin
    {
        OpeningSignature[] memory openingSignatures = abi.decode(openingSignaturesEncoded, (OpeningSignature[]));

        if (
            openingSignatures[0].accountOwner != onBehalfOf
                || openingSignatures[0].creditManager != ICreditFacadeV3(msg.sender).creditManager()
        ) {
            revert InvalidSignatureParamsException();
        }

        _approveOpening(openingSignatures);
        _burn(onBehalfOf, openingSignatures[0].creditManager);
    }

    /// @notice Records an opening approval if both EIP-712 signatures are valid
    /// @param openingSignatures Array of opening signature structs
    function approveOpening(OpeningSignature[] memory openingSignatures) external {
        _approveOpening(openingSignatures);
    }

    /// @dev Consumes the opening approval for `accountOwner` on `creditManager`
    /// @dev Reverts if the approval is missing or expired
    function _burn(address accountOwner, address creditManager) internal {
        if (block.timestamp > openingDeadlines[accountOwner][creditManager].deadline) revert CannotOpenException();
        openingDeadlines[accountOwner][creditManager].deadline = 0;

        if (nextDegenNFT != address(0)) {
            IDegenNFT(nextDegenNFT).burn(accountOwner, 1);
        }

        emit Burn(accountOwner, creditManager);
    }

    /// @dev Validates all signatures and stores the opening deadline if the signer count satisfies `minSignaturesRequired`
    function _approveOpening(OpeningSignature[] memory openingSignatures) internal {
        address creditManager;
        address accountOwner;
        uint32 deadline;
        uint32 nonce;
        bytes32 digest;
        uint16 nSignatures;
        address prevSigner;

        for (uint256 i = 0; i < openingSignatures.length; i++) {
            if (i == 0) {
                creditManager = openingSignatures[i].creditManager;
                accountOwner = openingSignatures[i].accountOwner;
                deadline = openingSignatures[i].deadline;
                nonce = openingSignatures[i].nonce;
                digest = _hashTypedDataV4(
                    keccak256(abi.encode(MINT_TYPEHASH, creditManager, accountOwner, deadline, nonce))
                );

                if (nonce != openingDeadlines[accountOwner][creditManager].nonce + 1) revert IncorrectNonceException();
            } else {
                if (
                    openingSignatures[i].creditManager != creditManager
                        || openingSignatures[i].accountOwner != accountOwner
                        || openingSignatures[i].deadline != deadline || openingSignatures[i].nonce != nonce
                ) revert OpeningParamsMismatchException();
            }

            address signer = ECDSA.recover(digest, openingSignatures[i].signature);
            if (uint160(signer) <= uint160(prevSigner)) revert IncorrectSignerSortingException();
            prevSigner = signer;

            if (IACL(acl).hasRole(ROLE_OPENING_SIGNER, signer)) nSignatures++;
        }

        if (nSignatures < minSignaturesRequired) revert NotEnoughSignersException();

        openingDeadlines[accountOwner][creditManager].deadline = deadline;
        openingDeadlines[accountOwner][creditManager].nonce = nonce;

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
