// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IGearStakingV3, VotingContractStatus} from "@gearbox-protocol/core-v3/contracts/interfaces/IGearStakingV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {IACL} from "../../interfaces/extensions/IACL.sol";
import {IACLLegacy} from "../../interfaces/extensions/IACLLegacy.sol";
import {IContractsRegister} from "../../interfaces/extensions/IContractsRegister.sol";
import {IContractsRegisterLegacy} from "../../interfaces/extensions/IContractsRegisterLegacy.sol";
import {Call} from "../../interfaces/Types.sol";

import {AP_MARKET_CONFIGURATOR_LEGACY} from "../../libraries/ContractLiterals.sol";

import {MarketConfigurator} from "../MarketConfigurator.sol";

contract MarketConfiguratorLegacy is MarketConfigurator {
    using Address for address;

    /// @notice Contract version
    uint256 public constant override version = 3_10;

    /// @notice Contract type
    bytes32 public constant override contractType = AP_MARKET_CONFIGURATOR_LEGACY;

    address public immutable aclLegacy;
    address public immutable contractsRegisterLegacy;
    address public immutable gearStakingLegacy;

    error AddressIsNotPausableAdminException(address admin);
    error AddressIsNotUnpausableAdminException(address admin);
    error CallsToLegacyContractsAreForbiddenException();
    error CreditManagerIsMisconfiguredException(address creditManager);

    /// @dev There's no way to validate that `pausableAdmins_` and `unpausableAdmins_` are exhaustive
    ///      because the legacy ACL contract doesn't provide needed getters, so don't screw up :)
    constructor(
        string memory name_,
        address marketConfiguratorFactory_,
        address riskCurator_,
        address treasury_,
        address aclLegacy_,
        address contractsRegisterLegacy_,
        address gearStakingLegacy_,
        address[] memory pausableAdmins_,
        address[] memory unpausableAdmins_,
        address[] memory emergencyLiquidators_
    ) MarketConfigurator(name_, marketConfiguratorFactory_, riskCurator_, treasury_) {
        aclLegacy = aclLegacy_;
        contractsRegisterLegacy = contractsRegisterLegacy_;
        gearStakingLegacy = gearStakingLegacy_;

        uint256 num = pausableAdmins_.length;
        for (uint256 i; i < num; ++i) {
            address admin = pausableAdmins_[i];
            if (!IACLLegacy(aclLegacy).isPausableAdmin(admin)) revert AddressIsNotPausableAdminException(admin);
            IACL(acl).addPausableAdmin(admin);
        }
        num = unpausableAdmins_.length;
        for (uint256 i; i < num; ++i) {
            address admin = unpausableAdmins_[i];
            if (!IACLLegacy(aclLegacy).isUnpausableAdmin(admin)) revert AddressIsNotUnpausableAdminException(admin);
            IACL(acl).addUnpausableAdmin(admin);
        }
        num = emergencyLiquidators_.length;
        for (uint256 i; i < num; ++i) {
            IACL(acl).addEmergencyLiquidator(emergencyLiquidators_[i]);
        }

        address[] memory pools = IContractsRegisterLegacy(contractsRegisterLegacy).getPools();
        uint256 numPools = pools.length;
        for (uint256 i; i < numPools; ++i) {
            address pool = pools[i];
            if (!_isV3Contract(pool)) continue;

            address[] memory creditManagers = IPoolV3(pool).creditManagers();
            uint256 numCreditManagers = creditManagers.length;
            if (numCreditManagers == 0) continue;

            address priceOracle = _priceOracle(creditManagers[0]);
            address lossLiquidator = _lossLiquidator(creditManagers[0]);
            IContractsRegister(contractsRegister).createMarket(pool, priceOracle, lossLiquidator);

            for (uint256 j; j < numCreditManagers; ++j) {
                address creditManager = creditManagers[j];
                // QUESTION: maybe revert with more detailed exceptions?
                if (
                    !_isV3Contract(creditManager) || _priceOracle(creditManager) != priceOracle
                        || _lossLiquidator(creditManager) != lossLiquidator
                ) {
                    revert CreditManagerIsMisconfiguredException(creditManager);
                }

                // QUESTION: check all tokens are quoted etc?

                IContractsRegister(contractsRegister).createCreditSuite(pool, creditManagers[j]);
            }

            // TODO: set factories, access lists etc
        }
    }

    function claimLegacyACLOwnership() external onlyOwner {
        // on some chains, legacy ACL implements a 2-step ownership transfer
        try IACLLegacy(aclLegacy).pendingOwner() {
            IACLLegacy(aclLegacy).claimOwnership();
        } catch {}
    }

    function createCreditSuite(address pool, bytes calldata encodedParams)
        public
        override
        returns (address creditManager)
    {
        creditManager = super.createCreditSuite(pool, encodedParams);
        IContractsRegisterLegacy(contractsRegisterLegacy).addCreditManager(creditManager);
    }

    function addPausableAdmin(address admin) public override {
        super.addPausableAdmin(admin);
        IACLLegacy(aclLegacy).addPausableAdmin(admin);
    }

    function addUnpausableAdmin(address admin) public override {
        super.addUnpausableAdmin(admin);
        IACLLegacy(aclLegacy).addUnpausableAdmin(admin);
    }

    function removePausableAdmin(address admin) public override {
        super.removePausableAdmin(admin);
        IACLLegacy(aclLegacy).removePausableAdmin(admin);
    }

    function removeUnpausableAdmin(address admin) public override {
        super.removeUnpausableAdmin(admin);
        IACLLegacy(aclLegacy).removeUnpausableAdmin(admin);
    }

    function migrate(address newMarketConfigurator) public override {
        super.migrate(newMarketConfigurator);
        IACLLegacy(aclLegacy).transferOwnership(newMarketConfigurator);
    }

    function setVotingContractStatus(address votingContract, VotingContractStatus status)
        external
        onlyMarketConfiguratorFactory
    {
        IGearStakingV3(gearStakingLegacy).setVotingContractStatus(votingContract, status);
    }

    function configureGearStaking(bytes calldata data) external onlyMarketConfiguratorFactory {
        gearStakingLegacy.functionCall(data);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _executeHook(address factory, Call[] memory calls) internal override {
        uint256 numCalls = calls.length;
        for (uint256 i; i < numCalls; ++i) {
            address target = calls[i].target;
            if (target == aclLegacy || target == contractsRegisterLegacy || target == gearStakingLegacy) {
                revert CallsToLegacyContractsAreForbiddenException();
            }
        }
        super._executeHook(factory, calls);
    }

    function _isV3Contract(address contract_) internal view returns (bool) {
        try IVersion(contract_).version() returns (uint256 version_) {
            return version_ >= 300 && version_ < 400;
        } catch {
            return false;
        }
    }

    function _priceOracle(address creditManager) internal view returns (address) {
        return ICreditManagerV3(creditManager).priceOracle();
    }

    function _lossLiquidator(address creditManager) internal view returns (address) {
        return ICreditFacadeV3(ICreditManagerV3(creditManager).creditFacade()).lossLiquidator();
    }
}
