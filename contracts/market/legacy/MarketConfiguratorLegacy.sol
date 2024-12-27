// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.23;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {ICreditFacadeV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditFacadeV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";

import {IACL} from "../../interfaces/extensions/IACL.sol";
import {IContractsRegister} from "../../interfaces/extensions/IContractsRegister.sol";
import {Call, MarketFactories} from "../../interfaces/Types.sol";

import {
    AP_MARKET_CONFIGURATOR_LEGACY,
    ROLE_EMERGENCY_LIQUIDATOR,
    ROLE_PAUSABLE_ADMIN,
    ROLE_UNPAUSABLE_ADMIN
} from "../../libraries/ContractLiterals.sol";

import {MarketConfigurator} from "../MarketConfigurator.sol";

interface IACLLegacy {
    function pendingOwner() external view returns (address);
    function transferOwnership(address newOwner) external;
    function claimOwnership() external;

    function isPausableAdmin(address account) external view returns (bool);
    function addPausableAdmin(address account) external;
    function removePausableAdmin(address account) external;

    function isUnpausableAdmin(address account) external view returns (bool);
    function addUnpausableAdmin(address account) external;
    function removeUnpausableAdmin(address account) external;
}

interface IContractsRegisterLegacy {
    function getPools() external view returns (address[] memory);
    function addPool(address pool) external;
    function addCreditManager(address creditManager) external;
}

// TODO: somehow need to add MC Legacy to MC Factory. maybe we can deploy it from there?

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
    error CallerIsNotMarketConfiguratorFactoryException(address caller);
    error CallsToLegacyContractsAreForbiddenException();
    error CreditManagerIsMisconfiguredException(address creditManager);
    error CollateralTokenIsNotQuotedException(address creditManager, address token);

    modifier onlyMarketConfiguratorFactory() {
        if (msg.sender != marketConfiguratorFactory) revert CallerIsNotMarketConfiguratorFactoryException(msg.sender);
        _;
    }

    /// @dev There's no way to validate that `pausableAdmins_` and `unpausableAdmins_` are exhaustive
    ///      because the legacy ACL contract doesn't provide needed getters, so don't screw up :)
    constructor(
        string memory curatorName_,
        address admin_,
        address emergencyAdmin_,
        address addressProvider_,
        address aclLegacy_,
        address contractsRegisterLegacy_,
        address gearStakingLegacy_,
        address[] memory pausableAdmins_,
        address[] memory unpausableAdmins_,
        address[] memory emergencyLiquidators_
    ) MarketConfigurator(curatorName_, admin_, emergencyAdmin_, addressProvider_) {
        aclLegacy = aclLegacy_;
        contractsRegisterLegacy = contractsRegisterLegacy_;
        gearStakingLegacy = gearStakingLegacy_;

        uint256 num = pausableAdmins_.length;
        for (uint256 i; i < num; ++i) {
            address admin = pausableAdmins_[i];
            if (!IACLLegacy(aclLegacy).isPausableAdmin(admin)) revert AddressIsNotPausableAdminException(admin);
            IACL(acl).grantRole(ROLE_PAUSABLE_ADMIN, admin);
        }
        num = unpausableAdmins_.length;
        for (uint256 i; i < num; ++i) {
            address admin = unpausableAdmins_[i];
            if (!IACLLegacy(aclLegacy).isUnpausableAdmin(admin)) revert AddressIsNotUnpausableAdminException(admin);
            IACL(acl).grantRole(ROLE_UNPAUSABLE_ADMIN, admin);
        }
        num = emergencyLiquidators_.length;
        for (uint256 i; i < num; ++i) {
            IACL(acl).grantRole(ROLE_EMERGENCY_LIQUIDATOR, emergencyLiquidators_[i]);
        }

        MarketFactories memory marketFactories = _getLatestMarketFactories(version);
        address creditFactory = _getLatestCreditFactory(version);

        address[] memory pools = IContractsRegisterLegacy(contractsRegisterLegacy).getPools();
        uint256 numPools = pools.length;
        for (uint256 i; i < numPools; ++i) {
            address pool = pools[i];
            if (!_isV3Contract(pool)) continue;

            address[] memory creditManagers = IPoolV3(pool).creditManagers();
            uint256 numCreditManagers = creditManagers.length;
            if (numCreditManagers == 0) continue;

            address quotaKeeper = _quotaKeeper(pool);
            address priceOracle = _priceOracle(creditManagers[0]);
            address lossLiquidator = _lossLiquidator(creditManagers[0]);

            IContractsRegister(contractsRegister).registerMarket(pool, priceOracle, lossLiquidator);
            _marketFactories[pool] = marketFactories;
            _authorizeFactory(marketFactories.poolFactory, pool, pool);
            _authorizeFactory(marketFactories.poolFactory, pool, quotaKeeper);
            _authorizeFactory(marketFactories.priceOracleFactory, pool, priceOracle);
            _authorizeFactory(marketFactories.interestRateModelFactory, pool, _interestRateModel(pool));
            _authorizeFactory(marketFactories.rateKeeperFactory, pool, _rateKeeper(quotaKeeper));
            _authorizeFactory(marketFactories.lossLiquidatorFactory, pool, lossLiquidator);

            for (uint256 j; j < numCreditManagers; ++j) {
                address creditManager = creditManagers[j];
                // QUESTION: maybe revert with more detailed exceptions?
                if (
                    !_isV3Contract(creditManager) || _priceOracle(creditManager) != priceOracle
                        || _lossLiquidator(creditManager) != lossLiquidator
                ) {
                    revert CreditManagerIsMisconfiguredException(creditManager);
                }

                uint256 numTokens = ICreditManagerV3(creditManager).collateralTokensCount();
                for (uint256 k = 1; k < numTokens; ++k) {
                    address token = ICreditManagerV3(creditManager).getTokenByMask(1 << k);
                    if (!IPoolQuotaKeeperV3(quotaKeeper).isQuotedToken(token)) {
                        revert CollateralTokenIsNotQuotedException(creditManager, token);
                    }
                }

                address creditConfigurator = ICreditManagerV3(creditManager).creditConfigurator();
                address creditFacade = ICreditManagerV3(creditManager).creditFacade();
                IContractsRegister(contractsRegister).registerCreditSuite(creditManager);
                _authorizeFactory(creditFactory, creditManager, creditConfigurator);
                _authorizeFactory(creditFactory, creditManager, creditFacade);

                address[] memory adapters = ICreditConfiguratorV3(creditConfigurator).allowedAdapters();
                uint256 numAdapters = adapters.length;
                for (uint256 k; k < numAdapters; ++k) {
                    // FIXME: getting stack too deep here
                    // _authorizeFactory(creditFactory, creditManager, adapters[k]);
                }
            }
        }
    }

    // ------------- //
    // CONFIGURATION //
    // ------------- //

    function claimLegacyACLOwnership() external onlyAdmin {
        // on some chains, legacy ACL implements a 2-step ownership transfer
        try IACLLegacy(aclLegacy).pendingOwner() {
            IACLLegacy(aclLegacy).claimOwnership();
        } catch {}
    }

    function configureGearStaking(bytes calldata data) external onlyMarketConfiguratorFactory {
        gearStakingLegacy.functionCall(data);
    }

    // --------- //
    // INTERNALS //
    // --------- //

    function _registerMarket(address pool, address priceOracle, address lossLiquidator) internal override {
        super._registerMarket(pool, priceOracle, lossLiquidator);
        IContractsRegisterLegacy(contractsRegisterLegacy).addPool(pool);
    }

    function _registerCreditSuite(address creditManager) internal override {
        super._registerCreditSuite(creditManager);
        IContractsRegisterLegacy(contractsRegisterLegacy).addCreditManager(creditManager);
    }

    function _grantRole(bytes32 role, address account) internal override {
        super._grantRole(role, account);
        if (role == ROLE_PAUSABLE_ADMIN) IACLLegacy(aclLegacy).addPausableAdmin(account);
        else if (role == ROLE_UNPAUSABLE_ADMIN) IACLLegacy(aclLegacy).addUnpausableAdmin(account);
    }

    function _revokeRole(bytes32 role, address account) internal override {
        super._revokeRole(role, account);
        if (role == ROLE_PAUSABLE_ADMIN) IACLLegacy(aclLegacy).removePausableAdmin(account);
        else if (role == ROLE_UNPAUSABLE_ADMIN) IACLLegacy(aclLegacy).removeUnpausableAdmin(account);
    }

    function _validateCallTarget(address target, address factory) internal override {
        super._validateCallTarget(target, factory);
        if (target == aclLegacy || target == contractsRegisterLegacy || target == gearStakingLegacy) {
            revert CallsToLegacyContractsAreForbiddenException();
        }
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
