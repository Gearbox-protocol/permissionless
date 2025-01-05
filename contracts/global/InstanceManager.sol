// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {BytecodeRepository} from "./BytecodeRepository.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract InstanceManager is Ownable2Step {
    BytecodeRepository public immutable bytecodeRepository;
}
