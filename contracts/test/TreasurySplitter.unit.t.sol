// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {TreasurySplitter} from "../market/TreasurySplitter.sol";
import {ITreasurySplitter, Split, TwoAdminProposal} from "../interfaces/ITreasurySplitter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";

contract MockAddressProvider {
    address public treasury;
    address public treasuryProxy;

    constructor(address _treasury, address _treasuryProxy) {
        treasury = _treasury;
        treasuryProxy = _treasuryProxy;
    }

    function getAddressOrRevert(bytes32 key, uint256) external view returns (address) {
        if (key == "TREASURY") return treasury;
        if (key == "TREASURY_PROXY") return treasuryProxy;
        revert();
    }
}

contract TreasurySplitterTest is Test {
    TreasurySplitter splitter;
    ERC20Mock token1;
    ERC20Mock token2;
    MockAddressProvider addressProvider;

    address admin;
    address treasury;
    address treasuryProxy;
    address receiver1;
    address receiver2;
    address receiver3;

    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        treasuryProxy = makeAddr("treasuryProxy");
        receiver1 = makeAddr("receiver1");
        receiver2 = makeAddr("receiver2");
        receiver3 = makeAddr("receiver3");

        addressProvider = new MockAddressProvider(treasury, treasuryProxy);
        splitter = new TreasurySplitter(address(addressProvider), admin);

        token1 = new ERC20Mock();
        token2 = new ERC20Mock();
    }

    /// @dev U:[TRS-1]: distribute works correctly
    function test_TRS_01_distribute() public {
        uint256 amount1 = 1000 * 1e18;
        token1.mint(address(splitter), amount1);

        vm.prank(admin);
        splitter.distribute(address(token1));

        assertEq(token1.balanceOf(admin), 500 * 1e18);
        assertEq(token1.balanceOf(treasury), 500 * 1e18);

        vm.prank(address(splitter));
        splitter.setTokenInsuranceAmount(address(token2), 300 * 1e18);

        uint256 amount2 = 1000 * 1e18;
        token2.mint(address(splitter), amount2);

        vm.prank(treasuryProxy);
        splitter.distribute(address(token2));

        uint256 distributableAmount = amount2 - 300 * 1e18;
        assertEq(token2.balanceOf(admin), distributableAmount / 2);
        assertEq(token2.balanceOf(treasury), distributableAmount / 2);
        assertEq(token2.balanceOf(address(splitter)), 300 * 1e18);
    }

    /// @dev U:[TRS-2]: configure and proposal management work correctly
    function test_TRS_02_configure() public {
        // Setup test data
        address[] memory receivers = new address[](2);
        receivers[0] = receiver1;
        receivers[1] = receiver2;

        uint16[] memory proportions = new uint16[](2);
        proportions[0] = 6000;
        proportions[1] = 4000;

        bytes memory setTokenSplitData =
            abi.encodeWithSelector(ITreasurySplitter.setTokenSplit.selector, address(token1), receivers, proportions);

        vm.prank(admin);
        splitter.configure(setTokenSplitData);

        TwoAdminProposal[] memory activeProposals = splitter.activeProposals();
        assertEq(activeProposals.length, 1);
        assertEq(activeProposals[0].callData, setTokenSplitData);
        assertTrue(activeProposals[0].confirmedByAdmin);
        assertFalse(activeProposals[0].confirmedByTreasuryProxy);

        vm.prank(treasuryProxy);
        splitter.configure(setTokenSplitData);

        activeProposals = splitter.activeProposals();
        assertEq(activeProposals.length, 0);

        Split memory split = splitter.tokenSplits(address(token1));
        assertTrue(split.initialized);

        bytes memory setDefaultSplitData =
            abi.encodeWithSelector(ITreasurySplitter.setDefaultSplit.selector, receivers, proportions);

        vm.prank(admin);
        splitter.configure(setDefaultSplitData);

        activeProposals = splitter.activeProposals();
        assertEq(activeProposals.length, 1);

        vm.prank(admin);
        splitter.cancelConfigure(setDefaultSplitData);

        activeProposals = splitter.activeProposals();
        assertEq(activeProposals.length, 0);

        bytes memory invalidData = abi.encodeWithSelector(bytes4(keccak256("invalidFunction()")), address(token1));

        vm.expectRevert(ITreasurySplitter.IncorrectConfigureSelectorException.selector);
        vm.prank(admin);
        splitter.configure(invalidData);
    }

    /// @dev U:[TRS-3]: setTokenInsuranceAmount works correctly
    function test_TRS_03_setTokenInsuranceAmount() public {
        // Mint initial tokens
        uint256 amount = 1000 * 1e18;
        token1.mint(address(splitter), amount);

        // Set insurance amount and verify
        vm.prank(address(splitter));
        splitter.setTokenInsuranceAmount(address(token1), 300 * 1e18);

        assertEq(splitter.tokenInsuranceAmount(address(token1)), 300 * 1e18);

        // Verify distribution with insurance amount
        uint256 distributableAmount = amount - 300 * 1e18;
        assertEq(token1.balanceOf(admin), distributableAmount / 2);
        assertEq(token1.balanceOf(treasury), distributableAmount / 2);
        assertEq(token1.balanceOf(address(splitter)), 300 * 1e18);

        // Test setting insurance amount higher than balance
        vm.prank(address(splitter));
        splitter.setTokenInsuranceAmount(address(token1), 400 * 1e18);

        // No additional distribution should occur
        assertEq(token1.balanceOf(admin), distributableAmount / 2);
        assertEq(token1.balanceOf(treasury), distributableAmount / 2);
        assertEq(token1.balanceOf(address(splitter)), 300 * 1e18);
    }

    /// @dev U:[TRS-4]: setTokenSplit works correctly
    function test_TRS_04_setTokenSplit() public {
        address[] memory receivers = new address[](2);
        receivers[0] = receiver1;
        receivers[1] = receiver2;

        uint16[] memory proportions = new uint16[](2);
        proportions[0] = 6000;
        proportions[1] = 4000;

        // Test normal split setup
        vm.prank(address(splitter));
        splitter.setTokenSplit(address(token1), receivers, proportions);

        Split memory tokenSplit = splitter.tokenSplits(address(token1));
        assertTrue(tokenSplit.initialized);
        assertEq(tokenSplit.receivers[0], receiver1);
        assertEq(tokenSplit.receivers[1], receiver2);
        assertEq(tokenSplit.proportions[0], 6000);
        assertEq(tokenSplit.proportions[1], 4000);

        // Test invalid split with wrong proportions sum
        proportions[1] = 3000;
        vm.expectRevert(ITreasurySplitter.PropotionSumIncorrectException.selector);
        vm.prank(address(splitter));
        splitter.setTokenSplit(address(token1), receivers, proportions);

        // Test invalid split with splitter as receiver
        receivers[0] = address(splitter);
        proportions[1] = 4000;
        vm.expectRevert(ITreasurySplitter.TreasurySplitterAsReceiverException.selector);
        vm.prank(address(splitter));
        splitter.setTokenSplit(address(token1), receivers, proportions);

        // Test access control
        vm.expectRevert(ITreasurySplitter.OnlySelfException.selector);
        splitter.setTokenSplit(address(token1), receivers, proportions);
    }

    /// @dev U:[TRS-5]: setDefaultSplit works correctly
    function test_TRS_05_setDefaultSplit() public {
        address[] memory receivers = new address[](2);
        receivers[0] = receiver1;
        receivers[1] = receiver2;

        uint16[] memory proportions = new uint16[](2);
        proportions[0] = 6000;
        proportions[1] = 4000;

        // Test normal split setup
        vm.prank(address(splitter));
        splitter.setDefaultSplit(receivers, proportions);

        Split memory defaultSplit = splitter.defaultSplit();
        assertTrue(defaultSplit.initialized);
        assertEq(defaultSplit.receivers[0], receiver1);
        assertEq(defaultSplit.receivers[1], receiver2);
        assertEq(defaultSplit.proportions[0], 6000);
        assertEq(defaultSplit.proportions[1], 4000);

        // Test invalid split with wrong proportions sum
        proportions[1] = 3000;
        vm.expectRevert(ITreasurySplitter.PropotionSumIncorrectException.selector);
        vm.prank(address(splitter));
        splitter.setDefaultSplit(receivers, proportions);

        // Test invalid split with splitter as receiver
        receivers[0] = address(splitter);
        proportions[1] = 4000;
        vm.expectRevert(ITreasurySplitter.TreasurySplitterAsReceiverException.selector);
        vm.prank(address(splitter));
        splitter.setDefaultSplit(receivers, proportions);

        // Test access control
        vm.expectRevert(ITreasurySplitter.OnlySelfException.selector);
        splitter.setDefaultSplit(receivers, proportions);
    }

    /// @dev U:[TRS-6]: withdrawToken works correctly
    function test_TRS_06_withdrawToken() public {
        uint256 amount = 1000 * 1e18;
        token1.mint(address(splitter), amount);

        // Test partial withdrawal
        vm.prank(address(splitter));
        splitter.withdrawToken(address(token1), receiver1, 500 * 1e18);

        assertEq(token1.balanceOf(receiver1), 500 * 1e18);
        assertEq(token1.balanceOf(address(splitter)), 500 * 1e18);

        // Test full withdrawal
        vm.prank(address(splitter));
        splitter.withdrawToken(address(token1), receiver2, 500 * 1e18);

        assertEq(token1.balanceOf(receiver2), 500 * 1e18);
        assertEq(token1.balanceOf(address(splitter)), 0);

        // Test access control
        vm.expectRevert(ITreasurySplitter.OnlySelfException.selector);
        splitter.withdrawToken(address(token1), receiver1, 100 * 1e18);
    }
}
