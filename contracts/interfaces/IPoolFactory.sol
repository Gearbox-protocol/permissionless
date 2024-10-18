// SPDX-License-Identifier: MIT
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2023.
pragma solidity ^0.8.17;

import {IModularFactory} from "./IModularFactory.sol";
import {Call} from "./Types.sol";

interface IPoolFactory is IModularFactory {
    function onAddToken(address _pool, address _token, address _priceFeed)
        external
        pure
        returns (Call[] memory calls);

    function onUpdateInterestModel(address pool, address _model) external view returns (Call[] memory calls);

    // CREDIT
    function onAddCreditManager(address pool, address newCreditManager) external returns (Call[] memory calls);
    function onRemoveCreditManager(address _creditManager) external returns (Call[] memory calls);
}
