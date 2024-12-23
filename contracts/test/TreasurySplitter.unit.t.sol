// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@gearbox-protocol/core-v3/contracts/test/lib/constants.sol";
import {TreasurySplitter} from "../market/TreasurySplitter.sol";
import {ITreasurySplitterEvents, ITreasurySplitterExceptions, Split} from "../interfaces/ITreasurySplitter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";

contract TreasurySplitterTest is Test, ITreasurySplitterEvents, ITreasurySplitterExceptions {
    TreasurySplitter splitter;
    ERC20Mock token1;
    ERC20Mock token2;

    address receiver1;
    address receiver2;
    address receiver3;

    function assertEq(uint16[] memory a, uint16[] memory b) internal pure {
        assertEq(a.length, b.length, "Uint16 array length mismatch");
        for (uint256 i = 0; i < a.length; i++) {
            assertEq(a[i], b[i], string(abi.encodePacked("Uint16 mismatch at index ", vm.toString(i))));
        }
    }

    function setUp() public {
        vm.prank(CONFIGURATOR);
        splitter = new TreasurySplitter();
        token1 = new ERC20Mock();
        token2 = new ERC20Mock();
        receiver1 = makeAddr("receiver1");
        receiver2 = makeAddr("receiver2");
        receiver3 = makeAddr("receiver3");
    }

    /// @dev U:[TRS-1]: distribute works correctly
    function test_TRS_01_distribute() public {
        ERC20Mock token3 = new ERC20Mock();
        token3.mint(address(splitter), 5000 * 10 ** 18);

        vm.expectRevert(UndefinedSplitException.selector);
        splitter.distribute(address(token3));

        address[] memory defaultReceivers = new address[](3);
        defaultReceivers[0] = receiver1;
        defaultReceivers[1] = receiver2;
        defaultReceivers[2] = address(splitter);

        uint16[] memory defaultProportions = new uint16[](3);
        defaultProportions[0] = 5000;
        defaultProportions[1] = 3000;
        defaultProportions[2] = 2000;

        vm.prank(CONFIGURATOR);
        splitter.setDefaultSplit(defaultReceivers, defaultProportions);

        uint256 amount1 = 1000 * 1e18;
        token1.mint(address(splitter), amount1);

        vm.expectEmit(true, false, false, true);
        emit DistributeToken(address(token1), amount1);
        splitter.distribute(address(token1));

        assertEq(token1.balanceOf(receiver1), 500 * 1e18);
        assertEq(token1.balanceOf(receiver2), 300 * 1e18);
        assertEq(token1.balanceOf(address(splitter)), 200 * 1e18);
        assertEq(splitter.lastBalance(address(token1)), 200 * 1e18);

        address[] memory tokenReceivers = new address[](3);
        tokenReceivers[0] = receiver1;
        tokenReceivers[1] = address(splitter);
        tokenReceivers[2] = receiver2;

        uint16[] memory tokenProportions = new uint16[](3);
        tokenProportions[0] = 4000;
        tokenProportions[1] = 4000;
        tokenProportions[2] = 2000;

        vm.prank(CONFIGURATOR);
        splitter.setTokenSplit(address(token2), tokenReceivers, tokenProportions);

        uint256 amount2 = 1000 * 1e18;
        token2.mint(address(splitter), amount2);

        vm.expectEmit(true, false, false, true);
        emit DistributeToken(address(token2), amount2);
        splitter.distribute(address(token2));

        assertEq(token2.balanceOf(receiver1), 400 * 1e18);
        assertEq(token2.balanceOf(receiver2), 200 * 1e18);
        assertEq(token2.balanceOf(address(splitter)), 400 * 1e18);
        assertEq(splitter.lastBalance(address(token2)), 400 * 1e18);

        uint256 amount3 = 500 * 1e18;
        token2.mint(address(splitter), amount3);

        vm.expectEmit(true, false, false, true);
        emit DistributeToken(address(token2), amount3);
        splitter.distribute(address(token2));

        assertEq(token2.balanceOf(receiver1), 600 * 1e18);
        assertEq(token2.balanceOf(receiver2), 300 * 1e18);
        assertEq(token2.balanceOf(address(splitter)), 600 * 1e18);
        assertEq(splitter.lastBalance(address(token2)), 600 * 1e18);
    }

    /// @dev U:[TRS-2]: setTokenSplit works correctly
    function test_TRS_02_setTokenSplit() public {
        address[] memory receivers = new address[](2);
        receivers[0] = receiver1;
        receivers[1] = receiver2;

        uint16[] memory proportions = new uint16[](2);
        proportions[0] = 6000;
        proportions[1] = 4000;

        vm.expectEmit(true, false, false, true);
        emit SetTokenSplit(address(token1), receivers, proportions);

        vm.prank(CONFIGURATOR);
        splitter.setTokenSplit(address(token1), receivers, proportions);

        Split memory split = splitter.tokenSplits(address(token1));

        assertTrue(split.initialized);
        assertEq(split.receivers.length, receivers.length, "Incorrect receivers array set");
        assertEq(split.proportions.length, proportions.length);

        proportions[1] = 3000;
        vm.expectRevert(PropotionSumIncorrectException.selector);
        vm.prank(CONFIGURATOR);
        splitter.setTokenSplit(address(token1), receivers, proportions);

        uint16[] memory shortProportions = new uint16[](1);
        shortProportions[0] = 10000;
        vm.expectRevert(SplitArraysDifferentLengthException.selector);
        vm.prank(CONFIGURATOR);
        splitter.setTokenSplit(address(token1), receivers, shortProportions);

        vm.prank(receiver1);
        vm.expectRevert("Ownable: caller is not the owner");
        splitter.setTokenSplit(address(token1), receivers, proportions);
    }

    /// @dev U:[TRS-3]: setDefaultSplit works correctly
    function test_TRS_03_setDefaultSplit() public {
        address[] memory receivers = new address[](3);
        receivers[0] = receiver1;
        receivers[1] = receiver2;
        receivers[2] = receiver3;

        uint16[] memory proportions = new uint16[](3);
        proportions[0] = 5000;
        proportions[1] = 3000;
        proportions[2] = 2000;

        vm.expectEmit(false, false, false, true);
        emit SetDefaultSplit(receivers, proportions);
        vm.prank(CONFIGURATOR);
        splitter.setDefaultSplit(receivers, proportions);

        Split memory split = splitter.defaultSplit();
        assertTrue(split.initialized);
        assertEq(split.receivers, receivers);
        assertEq(split.proportions, proportions);

        proportions[2] = 1000;
        vm.expectRevert(PropotionSumIncorrectException.selector);
        vm.prank(CONFIGURATOR);
        splitter.setDefaultSplit(receivers, proportions);

        uint16[] memory shortProportions = new uint16[](2);
        shortProportions[0] = 5000;
        shortProportions[1] = 5000;
        vm.expectRevert(SplitArraysDifferentLengthException.selector);
        vm.prank(CONFIGURATOR);
        splitter.setDefaultSplit(receivers, shortProportions);

        vm.prank(receiver1);
        vm.expectRevert("Ownable: caller is not the owner");
        splitter.setDefaultSplit(receivers, proportions);
    }

    /// @dev U:[TRS-4]: withdrawToken works correctly
    function test_TRS_04_withdrawToken() public {
        uint256 amount = 1000 * 10 ** 18;
        token1.mint(address(splitter), amount);

        vm.expectEmit(true, false, false, true);
        emit WithdrawToken(address(token1), receiver1, 300 * 10 ** 18);
        vm.prank(CONFIGURATOR);
        splitter.withdrawToken(address(token1), receiver1, 300 * 10 ** 18);

        assertEq(token1.balanceOf(receiver1), 300 * 10 ** 18);
        assertEq(token1.balanceOf(address(splitter)), 700 * 10 ** 18);
        assertEq(splitter.lastBalance(address(token1)), 700 * 10 ** 18);

        vm.prank(receiver1);
        vm.expectRevert("Ownable: caller is not the owner");
        splitter.withdrawToken(address(token1), receiver1, 300 * 10 ** 18);
    }
}
