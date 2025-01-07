// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {BytecodeRepository} from "./BytecodeRepository.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {AP_INSTANCE_MANAGER, AP_TREASURY, NO_VERSION_CONTROL} from "../libraries/ContractLiterals.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {LibString} from "@solady/utils/LibString.sol";

contract InstanceManager is Ownable {
    using LibString for bytes32;

    BytecodeRepository public immutable bytecodeRepository;

    address public crossChainGovernance;

    address public addressProvider;
    address public marketConfiguratorFactory;
    address public priceFeedStore;

    modifier onlyCrossChainGovernance() {
        require(msg.sender == crossChainGovernance, "Only cross-chain governance can call this function");
        _;
    }

    modifier onlyTreasury() {
        require(
            msg.sender
                == IAddressProvider(addressProvider).getAddressOrRevert(AP_TREASURY.fromSmallString(), NO_VERSION_CONTROL),
            "Only financial multisig can call this function"
        );
        _;
    }

    constructor(address _bytecodeRepository, address _owner) {
        bytecodeRepository = BytecodeRepository(_bytecodeRepository);
        crossChainGovernance = _owner;
        _transferOwnership(_owner);
    }

    function activate(address _instanceOwner, address _treasury) external onlyOwner {
        if (!isInstanceActivated()) {
            _verifyCoreContractsDeploy();
            _transferOwnership(_instanceOwner);
            IAddressProvider(addressProvider).setAddress(AP_INSTANCE_MANAGER.fromSmallString(), address(this), true);
            IAddressProvider(addressProvider).setAddress(AP_TREASURY.fromSmallString(), _treasury, false);
        }
    }

    function updateSystemAddressProvider(address _systemAddressProvider) external onlyCrossChainGovernance {}

    function updateInstanceAddressProvider(address _instance) external onlyOwner {
        // updates for DOMAIN
    }

    function updateFinancialMultisig(address _treasury) external onlyTreasury {
        // updates for DOMAIN
    }

    function _verifyCoreContractsDeploy() internal view {
        // verify that all core contracts are deployed
    }

    function transferCrossChainGovernance(address _newCrossChainGovernance) external onlyCrossChainGovernance {
        crossChainGovernance = _newCrossChainGovernance;
    }

    function isInstanceActivated() public view returns (bool) {
        return owner() != crossChainGovernance;
    }
}
