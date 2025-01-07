// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.23;

import {BytecodeRepository} from "./BytecodeRepository.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {
    AP_INSTANCE_MANAGER,
    AP_CROSS_CHAIN_GOVERNANCE,
    AP_TREASURY,
    NO_VERSION_CONTROL,
    AP_BYTECODE_REPOSITORY,
    AP_ADDRESS_PROVIDER,
    AP_INSTANCE_MANAGER_PROXY,
    AP_CROSS_CHAIN_GOVERNANCE_PROXY,
    AP_TREASURY_PROXY
} from "../libraries/ContractLiterals.sol";
import {IAddressProvider} from "../interfaces/IAddressProvider.sol";
import {ProxyCall} from "../helpers/ProxyCall.sol";
import {LibString} from "@solady/utils/LibString.sol";
import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {AddressProvider} from "./AddressProvider.sol";

contract InstanceManager is Ownable {
    using LibString for string;

    address public immutable addressProvider;
    address public immutable bytecodeRepository;

    address public instanceManagerProxy;
    address public treasuryProxy;
    address public crossChainGovernanceProxy;

    address public marketConfiguratorFactory;
    address public priceFeedStore;

    bool public isActivated;

    error InvalidKeyException(string key);

    modifier onlyCrossChainGovernance() {
        require(
            msg.sender
                == IAddressProvider(addressProvider).getAddressOrRevert(AP_CROSS_CHAIN_GOVERNANCE, NO_VERSION_CONTROL),
            "Only financial multisig can call this function"
        );
        _;
    }

    modifier onlyTreasury() {
        require(
            msg.sender == IAddressProvider(addressProvider).getAddressOrRevert(AP_TREASURY, NO_VERSION_CONTROL),
            "Only financial multisig can call this function"
        );
        _;
    }

    constructor(address _owner) {
        bytecodeRepository = address(new BytecodeRepository(address(this)));
        addressProvider = address(new AddressProvider());

        IAddressProvider(addressProvider).setAddress(AP_BYTECODE_REPOSITORY, address(bytecodeRepository), true);
        IAddressProvider(addressProvider).setAddress(AP_INSTANCE_MANAGER, address(this), true);
        IAddressProvider(addressProvider).setAddress(AP_CROSS_CHAIN_GOVERNANCE, _owner, false);

        instanceManagerProxy = address(new ProxyCall());
        treasuryProxy = address(new ProxyCall());
        crossChainGovernanceProxy = address(new ProxyCall());

        IAddressProvider(addressProvider).setAddress(AP_INSTANCE_MANAGER_PROXY, instanceManagerProxy, false);
        IAddressProvider(addressProvider).setAddress(AP_TREASURY_PROXY, treasuryProxy, false);
        IAddressProvider(addressProvider).setAddress(AP_CROSS_CHAIN_GOVERNANCE_PROXY, crossChainGovernanceProxy, false);

        _transferOwnership(_owner);
    }

    function activate(address _instanceOwner, address _treasury) external onlyOwner {
        if (!isActivated) {
            _verifyCoreContractsDeploy();
            _transferOwnership(_instanceOwner);

            IAddressProvider(addressProvider).setAddress(AP_TREASURY, _treasury, false);
            isActivated = true;
        }
    }

    function deploySystemContract(bytes32 _contractName, uint256 _version) external onlyCrossChainGovernance {
        // deploy contract
        // set address in address provider
        address newSystemContract =
            BytecodeRepository(bytecodeRepository).deploy(_contractName, _version, abi.encode(addressProvider), 0);
        IAddressProvider(addressProvider).setAddress(_contractName, newSystemContract, true);
    }

    function setAddress(string memory key, address addr, bool saveVersion) external onlyCrossChainGovernance {
        IAddressProvider(addressProvider).setAddress(key, addr, saveVersion);
    }

    function setLocalAddress(string memory key, address addr, bool saveVersion) external onlyOwner {
        if (!key.startsWith("LOCAL_")) {
            revert InvalidKeyException(key);
        }
        IAddressProvider(addressProvider).setAddress(key, addr, saveVersion);
    }

    function _verifyCoreContractsDeploy() internal view {
        // verify that all core contracts are deployed
    }

    function configureGlobal(address target, bytes calldata data) external onlyCrossChainGovernance {
        ProxyCall(crossChainGovernanceProxy).proxyCall(target, data);
    }

    function configureLocal(address target, bytes calldata data) external onlyOwner {
        ProxyCall(instanceManagerProxy).proxyCall(target, data);
    }

    function configureTreasury(address target, bytes calldata data) external onlyTreasury {
        ProxyCall(treasuryProxy).proxyCall(target, data);
    }
}
