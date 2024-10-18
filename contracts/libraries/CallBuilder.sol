// SPDX-License-Identifier: UNLICENSED
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {Call} from "../interfaces/Types.sol";

library CallBuilder {
    function build() internal pure returns (Call[] memory calls) {}

    function build(Call memory call1) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = call1;
    }

    function build(Call memory call1, Call memory call2) internal pure returns (Call[] memory calls) {
        calls = new Call[](2);
        calls[0] = call1;
        calls[1] = call2;
    }

    function build(Call memory call1, Call memory call2, Call memory call3)
        internal
        pure
        returns (Call[] memory calls)
    {
        calls = new Call[](3);
        calls[0] = call1;
        calls[1] = call2;
        calls[2] = call3;
    }

    function build(Call memory call1, Call memory call2, Call memory call3, Call memory call4)
        internal
        pure
        returns (Call[] memory calls)
    {
        calls = new Call[](4);
        calls[0] = call1;
        calls[1] = call2;
        calls[2] = call3;
        calls[3] = call4;
    }

    function build(Call memory call1, Call memory call2, Call memory call3, Call memory call4, Call memory call5)
        internal
        pure
        returns (Call[] memory calls)
    {
        calls = new Call[](5);
        calls[0] = call1;
        calls[1] = call2;
        calls[2] = call3;
        calls[3] = call4;
        calls[4] = call5;
    }

    function build(
        Call memory call1,
        Call memory call2,
        Call memory call3,
        Call memory call4,
        Call memory call5,
        Call memory call6
    ) internal pure returns (Call[] memory calls) {
        calls = new Call[](6);
        calls[0] = call1;
        calls[1] = call2;
        calls[2] = call3;
        calls[3] = call4;
        calls[4] = call5;
        calls[5] = call6;
    }
}
