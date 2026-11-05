// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2025.
pragma solidity ^0.8.23;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {ConfigurationTestHelper} from "../configuration/ConfigurationTestHelper.sol";
import {SignatureDegenNFT} from "../../helpers/SignatureDegenNFT.sol";

contract InvalidCreditFacade {
    address public creditManager;

    constructor(address _creditManager) {
        creditManager = _creditManager;
    }
}

contract SignatureDegenNFTTest is ConfigurationTestHelper {
    SignatureDegenNFT public degenNFT;

    uint256 internal gearboxSignerPrivateKey;
    uint256 internal curatorSignerPrivateKey;
    address internal gearboxSigner;
    address internal curatorSigner;

    address internal user1;
    address internal user2;
    address internal invalidCreditFacade;

    uint32 internal deadline;

    function setUp() public override {
        super.setUp();

        gearboxSignerPrivateKey = _generatePrivateKey("GEARBOX_SIGNER");
        curatorSignerPrivateKey = _generatePrivateKey("CURATOR_SIGNER");
        gearboxSigner = vm.addr(gearboxSignerPrivateKey);
        curatorSigner = vm.addr(curatorSignerPrivateKey);

        degenNFT = new SignatureDegenNFT(address(marketConfigurator), gearboxSigner, curatorSigner);

        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        invalidCreditFacade = address(new InvalidCreditFacade(address(creditManager)));
        deadline = uint32(block.timestamp + 1 days);
    }

    // ---- //
    // MINT //
    // ---- //

    function test_SD_01_approveOpening_success() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);

        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.ApproveOpening(user1, address(creditManager), deadline);

        degenNFT.approveOpening(address(creditManager), user1, deadline, gearboxSignature, curatorSignature);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), deadline, "Deadline not stored");
    }

    function test_SD_02_approveOpening_revertsOnInvalidGearboxSignature() public {
        (, bytes memory curatorSignature) = _signMint(address(creditManager), user1, deadline);
        bytes memory badGearboxSignature = _sign(curatorSignerPrivateKey, _mintDigest(address(creditManager), user1, deadline));

        vm.expectRevert(SignatureDegenNFT.InvalidGearboxSignatureException.selector);
        degenNFT.approveOpening(address(creditManager), user1, deadline, badGearboxSignature, curatorSignature);
    }

    function test_SD_03_approveOpening_revertsOnInvalidCuratorSignature() public {
        (bytes memory gearboxSignature,) = _signMint(address(creditManager), user1, deadline);
        bytes memory badCuratorSignature = _sign(gearboxSignerPrivateKey, _mintDigest(address(creditManager), user1, deadline));

        vm.expectRevert(SignatureDegenNFT.InvalidCuratorSignatureException.selector);
        degenNFT.approveOpening(address(creditManager), user1, deadline, gearboxSignature, badCuratorSignature);
    }

    function test_SD_04_approveOpening_revertsOnTamperedParams() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);

        vm.expectRevert(SignatureDegenNFT.InvalidGearboxSignatureException.selector);
        degenNFT.approveOpening(address(creditManager), user2, deadline, gearboxSignature, curatorSignature);
    }

    // ---- //
    // BURN //
    // ---- //

    function test_SD_05_burn_byCreditFacade() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);
        degenNFT.approveOpening(address(creditManager), user1, deadline, gearboxSignature, curatorSignature);

        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.Burn(user1, address(creditManager));

        vm.prank(address(creditFacade));
        degenNFT.burn(user1, 1);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), 0, "Deadline not cleared");
    }

    function test_SD_06_burn_revertsWithoutApproval() public {
        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.CannotOpenException.selector);
        degenNFT.burn(user1, 1);
    }

    function test_SD_07_burn_revertsIfExpired() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);
        degenNFT.approveOpening(address(creditManager), user1, deadline, gearboxSignature, curatorSignature);

        vm.warp(uint256(deadline) + 1);

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.CannotOpenException.selector);
        degenNFT.burn(user1, 1);
    }

    function test_SD_08_burn_revertsIfUnauthorized() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);
        degenNFT.approveOpening(address(creditManager), user1, deadline, gearboxSignature, curatorSignature);

        vm.prank(invalidCreditFacade);
        vm.expectRevert(
            abi.encodeWithSelector(
                SignatureDegenNFT.CallerIsNotCreditFacadeOrEmergencyAdminException.selector, invalidCreditFacade
            )
        );
        degenNFT.burn(user1, 1);
    }

    function test_SD_09_burn_withSignatureData() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);

        bytes memory signatureData =
            abi.encode(address(creditManager), user1, deadline, gearboxSignature, curatorSignature);

        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.ApproveOpening(user1, address(creditManager), deadline);
        vm.expectEmit(true, true, true, true);
        emit SignatureDegenNFT.Burn(user1, address(creditManager));

        vm.prank(address(creditFacade));
        degenNFT.burn(user1, 1, signatureData);

        assertEq(degenNFT.openingDeadlines(user1, address(creditManager)), 0, "Deadline not cleared");
    }

    function test_SD_10_burn_withSignatureData_revertsOnMismatchedOwner() public {
        (bytes memory gearboxSignature, bytes memory curatorSignature) =
            _signMint(address(creditManager), user1, deadline);

        bytes memory signatureData =
            abi.encode(address(creditManager), user1, deadline, gearboxSignature, curatorSignature);

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.InvalidSignatureParamsException.selector);
        degenNFT.burn(user2, 1, signatureData);
    }

    function test_SD_11_burn_withSignatureData_revertsOnMismatchedCreditManager() public {
        address otherCreditManager = makeAddr("otherCreditManager");
        (bytes memory gearboxSignature, bytes memory curatorSignature) = _signMint(otherCreditManager, user1, deadline);

        bytes memory signatureData = abi.encode(otherCreditManager, user1, deadline, gearboxSignature, curatorSignature);

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.InvalidSignatureParamsException.selector);
        degenNFT.burn(user1, 1, signatureData);
    }

    function test_SD_12_burn_withSignatureData_revertsOnInvalidSignature() public {
        (bytes memory gearboxSignature,) = _signMint(address(creditManager), user1, deadline);
        bytes memory badCuratorSignature = _sign(gearboxSignerPrivateKey, _mintDigest(address(creditManager), user1, deadline));

        bytes memory signatureData =
            abi.encode(address(creditManager), user1, deadline, gearboxSignature, badCuratorSignature);

        vm.prank(address(creditFacade));
        vm.expectRevert(SignatureDegenNFT.InvalidCuratorSignatureException.selector);
        degenNFT.burn(user1, 1, signatureData);
    }

    // --------- //
    // SERIALIZE //
    // --------- //

    function test_SD_13_serialize() public view {
        bytes memory expected =
            abi.encode(address(marketConfigurator), address(marketConfigurator.contractsRegister()), gearboxSigner, curatorSigner);
        assertEq(degenNFT.serialize(), expected, "Incorrect serialization");
    }

    // --------- //
    // HELPERS   //
    // --------- //

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("SignatureDegenNFT")),
                keccak256(bytes("1")),
                block.chainid,
                address(degenNFT)
            )
        );
    }

    function _mintDigest(address creditManager_, address accountOwner, uint32 deadline_)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash =
            keccak256(abi.encode(degenNFT.MINT_TYPEHASH(), creditManager_, accountOwner, deadline_));
        return ECDSA.toTypedDataHash(_domainSeparator(), structHash);
    }

    function _signMint(address creditManager_, address accountOwner, uint32 deadline_)
        internal
        view
        returns (bytes memory gearboxSignature, bytes memory curatorSignature)
    {
        bytes32 digest = _mintDigest(creditManager_, accountOwner, deadline_);
        gearboxSignature = _sign(gearboxSignerPrivateKey, digest);
        curatorSignature = _sign(curatorSignerPrivateKey, digest);
    }
}
