// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ConfigurationTestHelper} from "../configuration/ConfigurationTestHelper.sol";
import {OpeningSignature, SignatureDegenNFT} from "../../helpers/SignatureDegenNFT.sol";
import {ROLE_OPENING_SIGNER} from "../../libraries/ContractLiterals.sol";

contract InvalidCreditFacade {
    address public creditManager;

    constructor(address _creditManager) {
        creditManager = _creditManager;
    }
}

contract MockNextDegenNFT {
    address public lastFrom;
    uint256 public lastAmount;
    uint256 public burnCalls;

    function burn(address from, uint256 amount) external {
        lastFrom = from;
        lastAmount = amount;
        ++burnCalls;
    }
}

contract SignatureDegenNFTTest is ConfigurationTestHelper {
    uint16 internal constant MIN_SIGNATURES = 2;

    SignatureDegenNFT public degenNFT;
    MockNextDegenNFT public nextDegenNFT;

    uint256 internal signer0PrivateKey;
    uint256 internal signer1PrivateKey;
    uint256 internal signer2PrivateKey;
    address internal signer0;
    address internal signer1;
    address internal signer2;

    address internal user1;
    address internal user2;
    address internal invalidCreditFacade;

    uint32 internal deadline;

    function setUp() public override {
        super.setUp();

        signer0PrivateKey = _generatePrivateKey("OPENING_SIGNER_0");
        signer1PrivateKey = _generatePrivateKey("OPENING_SIGNER_1");
        signer2PrivateKey = _generatePrivateKey("OPENING_SIGNER_2");
        signer0 = vm.addr(signer0PrivateKey);
        signer1 = vm.addr(signer1PrivateKey);
        signer2 = vm.addr(signer2PrivateKey);

        vm.startPrank(admin);
        marketConfigurator.grantRole(ROLE_OPENING_SIGNER, signer0);
        marketConfigurator.grantRole(ROLE_OPENING_SIGNER, signer1);
        vm.stopPrank();

        nextDegenNFT = new MockNextDegenNFT();
        degenNFT = new SignatureDegenNFT(address(marketConfigurator), MIN_SIGNATURES, address(nextDegenNFT));

        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        invalidCreditFacade = address(new InvalidCreditFacade(address(creditManager)));
        deadline = uint32(block.timestamp + 1 days);
    }

    // ------------- //
    // APPROVE OPENING //
    // ------------- //

    function test_SD_01_approveOpening_success() public {
        OpeningSignature[] memory sigs = _signedOpenings(address(creditManager), user1, deadline, 2);

        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.ApproveOpening(user1, address(creditManager), deadline);

        degenNFT.approveOpening(sigs);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), deadline, "Deadline not stored");
    }

    function test_SD_02_approveOpening_revertsIfNotEnoughSigners() public {
        OpeningSignature[] memory sigs = new OpeningSignature[](2);
        bytes32 digest = _mintDigest(address(creditManager), user1, deadline);

        // signer2 does not have ROLE_OPENING_SIGNER
        sigs[0] = OpeningSignature({
            creditManager: address(creditManager),
            accountOwner: user1,
            deadline: deadline,
            signature: _sign(signer0PrivateKey, digest)
        });
        sigs[1] = OpeningSignature({
            creditManager: address(creditManager),
            accountOwner: user1,
            deadline: deadline,
            signature: _sign(signer2PrivateKey, digest)
        });

        vm.expectRevert(SignatureDegenNFT.NotEnoughSignersException.selector);
        degenNFT.approveOpening(sigs);
    }

    function test_SD_03_approveOpening_revertsIfBelowThreshold() public {
        OpeningSignature[] memory sigs = _signedOpenings(address(creditManager), user1, deadline, 1);

        vm.expectRevert(SignatureDegenNFT.NotEnoughSignersException.selector);
        degenNFT.approveOpening(sigs);
    }

    function test_SD_04_approveOpening_revertsOnParamsMismatch() public {
        OpeningSignature[] memory sigs = _signedOpenings(address(creditManager), user1, deadline, 2);
        sigs[1].accountOwner = user2;

        vm.expectRevert(SignatureDegenNFT.OpeningParamsMismatchException.selector);
        degenNFT.approveOpening(sigs);
    }

    function test_SD_05_approveOpening_ignoresNonRoleSignersTowardThreshold() public {
        OpeningSignature[] memory sigs = new OpeningSignature[](3);
        bytes32 digest = _mintDigest(address(creditManager), user1, deadline);

        sigs[0] = OpeningSignature({
            creditManager: address(creditManager),
            accountOwner: user1,
            deadline: deadline,
            signature: _sign(signer0PrivateKey, digest)
        });
        sigs[1] = OpeningSignature({
            creditManager: address(creditManager),
            accountOwner: user1,
            deadline: deadline,
            signature: _sign(signer2PrivateKey, digest)
        });
        sigs[2] = OpeningSignature({
            creditManager: address(creditManager),
            accountOwner: user1,
            deadline: deadline,
            signature: _sign(signer1PrivateKey, digest)
        });

        degenNFT.approveOpening(sigs);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), deadline, "Deadline not stored");
    }

    // ---- //
    // BURN //
    // ---- //

    function test_SD_06_burn_byCreditFacade() public {
        degenNFT.approveOpening(_signedOpenings(address(creditManager), user1, deadline, 2));

        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.Burn(user1, address(creditManager));

        vm.prank(address(creditFacade));
        degenNFT.burn(user1, 1);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), 0, "Deadline not cleared");
        assertEq(nextDegenNFT.burnCalls(), 1, "Next degen NFT not burned");
        assertEq(nextDegenNFT.lastFrom(), user1, "Incorrect next burn from");
        assertEq(nextDegenNFT.lastAmount(), 1, "Incorrect next burn amount");
    }

    function test_SD_07_burn_revertsWithoutApproval() public {
        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.CannotOpenException.selector);
        degenNFT.burn(user1, 1);
    }

    function test_SD_08_burn_revertsIfExpired() public {
        degenNFT.approveOpening(_signedOpenings(address(creditManager), user1, deadline, 2));

        vm.warp(uint256(deadline) + 1);

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.CannotOpenException.selector);
        degenNFT.burn(user1, 1);
    }

    function test_SD_09_burn_revertsIfUnauthorized() public {
        degenNFT.approveOpening(_signedOpenings(address(creditManager), user1, deadline, 2));

        vm.prank(invalidCreditFacade);
        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureDegenNFT.CallerIsNotCreditFacadeOrEmergencyAdminException.selector, invalidCreditFacade
            )
        );
        degenNFT.burn(user1, 1);
    }

    function test_SD_10_burn_withoutNextDegenNFT() public {
        SignatureDegenNFT standalone =
            new SignatureDegenNFT(address(marketConfigurator), MIN_SIGNATURES, address(0));

        OpeningSignature[] memory sigs = _signedOpeningsFor(standalone, address(creditManager), user1, deadline, 2);
        standalone.approveOpening(sigs);

        vm.prank(address(creditFacade));
        standalone.burn(user1, 1);

        assertEq(standalone.openingDeadlines(user1, address(creditManager)), 0, "Deadline not cleared");
        assertEq(nextDegenNFT.burnCalls(), 0, "Next degen NFT should not be called");
    }

    function test_SD_11_burn_withSignatureData() public {
        OpeningSignature[] memory sigs = _signedOpenings(address(creditManager), user1, deadline, 2);
        bytes memory encoded = abi.encode(sigs);

        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.ApproveOpening(user1, address(creditManager), deadline);
        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.Burn(user1, address(creditManager));

        vm.prank(address(creditFacade));
        degenNFT.burn(user1, 1, encoded);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), 0, "Deadline not cleared");
        assertEq(nextDegenNFT.burnCalls(), 1, "Next degen NFT not burned");
    }

    function test_SD_12_burn_withSignatureData_revertsOnMismatchedOwner() public {
        bytes memory encoded = abi.encode(_signedOpenings(address(creditManager), user1, deadline, 2));

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.InvalidSignatureParamsException.selector);
        degenNFT.burn(user2, 1, encoded);
    }

    function test_SD_13_burn_withSignatureData_revertsOnMismatchedCreditManager() public {
        address otherCreditManager = makeAddr("otherCreditManager");
        bytes memory encoded = abi.encode(_signedOpenings(otherCreditManager, user1, deadline, 2));

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.InvalidSignatureParamsException.selector);
        degenNFT.burn(user1, 1, encoded);
    }

    function test_SD_14_burn_withSignatureData_revertsIfNotEnoughSigners() public {
        OpeningSignature[] memory sigs = _signedOpenings(address(creditManager), user1, deadline, 1);
        bytes memory encoded = abi.encode(sigs);

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.NotEnoughSignersException.selector);
        degenNFT.burn(user1, 1, encoded);
    }

    // --------- //
    // SERIALIZE //
    // --------- //

    function test_SD_15_serialize() public view {
        bytes memory expected = abi.encode(
            address(marketConfigurator),
            address(marketConfigurator.contractsRegister()),
            MIN_SIGNATURES,
            address(nextDegenNFT)
        );
        assertEq(degenNFT.serialize(), expected, "Incorrect serialization");
    }

    // ------- //
    // HELPERS //
    // ------- //

    function _domainSeparator(SignatureDegenNFT nft) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SignatureDegenNFT")),
                keccak256(bytes("3_10")),
                block.chainid,
                address(nft)
            )
        );
    }

    function _mintDigest(SignatureDegenNFT nft, address creditManager_, address accountOwner, uint32 deadline_)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(nft.MINT_TYPEHASH(), creditManager_, accountOwner, deadline_));
        return ECDSA.toTypedDataHash(_domainSeparator(nft), structHash);
    }

    function _mintDigest(address creditManager_, address accountOwner, uint32 deadline_)
        internal
        view
        returns (bytes32)
    {
        return _mintDigest(degenNFT, creditManager_, accountOwner, deadline_);
    }

    function _signedOpenings(address creditManager_, address accountOwner, uint32 deadline_, uint256 count)
        internal
        view
        returns (OpeningSignature[] memory)
    {
        return _signedOpeningsFor(degenNFT, creditManager_, accountOwner, deadline_, count);
    }

    function _signedOpeningsFor(
        SignatureDegenNFT nft,
        address creditManager_,
        address accountOwner,
        uint32 deadline_,
        uint256 count
    ) internal view returns (OpeningSignature[] memory sigs) {
        uint256[3] memory keys = [signer0PrivateKey, signer1PrivateKey, signer2PrivateKey];
        bytes32 digest = _mintDigest(nft, creditManager_, accountOwner, deadline_);

        sigs = new OpeningSignature[](count);
        for (uint256 i; i < count; ++i) {
            sigs[i] = OpeningSignature({
                creditManager: creditManager_,
                accountOwner: accountOwner,
                deadline: deadline_,
                signature: _sign(keys[i], digest)
            });
        }
    }
}
