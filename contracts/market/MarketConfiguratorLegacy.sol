// SPDX-License-Identifier: BUSL-1.1
// Gearbox Protocol. Generalized leverage for DeFi protocols
// (c) Gearbox Foundation, 2024.
pragma solidity ^0.8.17;

import {ACLTrait} from "@gearbox-protocol/core-v3/contracts/traits/ACLTrait.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {PriceOracleFactoryV3} from "../factories/PriceOracleFactoryV3.sol";
import {InterestModelFactory} from "../factories/InterestModelFactory.sol";
import {PoolFactoryV3} from "../factories/PoolFactoryV3.sol";
import {CreditFactoryV3} from "../factories/CreditFactoryV3.sol";
import {AdapterFactoryV3} from "../factories/AdapterFactoryV3.sol";

import {PoolV3} from "@gearbox-protocol/core-v3/contracts/pool/PoolV3.sol";

import {IMarketConfiguratorV3} from "../interfaces/IMarketConfiguratorV3.sol";

import {
    IPriceOracleV3,
    PriceFeedParams,
    PriceUpdate
} from "@gearbox-protocol/core-v3/contracts/interfaces/IPriceOracleV3.sol";
import {ICreditManagerV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditManagerV3.sol";
import {ICreditConfiguratorV3} from "@gearbox-protocol/core-v3/contracts/interfaces/ICreditConfiguratorV3.sol";
import {IContractsRegister} from "../interfaces/IContractsRegister.sol";
import {IPoolV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolV3.sol";
import {IPoolQuotaKeeperV3} from "@gearbox-protocol/core-v3/contracts/interfaces/IPoolQuotaKeeperV3.sol";

import {IVersion} from "@gearbox-protocol/core-v3/contracts/interfaces/base/IVersion.sol";
import {IAddressProviderV3} from "../interfaces/IAddressProviderV3.sol";
import {IContractsRegister} from "../interfaces/IContractsRegister.sol";
import {IACL} from "../interfaces/IACL.sol";

import {ACL} from "./ACL.sol";

import {
    AP_ACCOUNT_FACTORY,
    AP_POOL,
    AP_POOL_QUOTA_KEEPER,
    AP_POOL_RATE_KEEPER,
    AP_PRICE_ORACLE,
    AP_CREDIT_MANAGER,
    AP_CREDIT_FACADE,
    AP_CREDIT_CONFIGURATOR,
    NO_VERSION_CONTROL
} from "../libraries/ContractLiterals.sol";
import {MarketConfigurator} from "./MarketConfigurator.sol";
import {AddressProviderV3} from "../global/AddressProviderV3.sol";
import {NO_VERSION_CONTROL} from "../libraries/ContractLiterals.sol";

// @notie it implements current migration from 3_0 to market structure

contract MarketConfiguratorLegacy is MarketConfigurator {
    using EnumerableSet for EnumerableSet.AddressSet;

    constructor(address _oldAddressProvider, address _newAddressProvider, string memory _name, address _vetoAdmin)
        MarketConfigurator(
            _newAddressProvider,
            IAddressProviderV3(_oldAddressProvider).getAddressOrRevert("ACL", NO_VERSION_CONTROL),
            IAddressProviderV3(_oldAddressProvider).getAddressOrRevert("CONTRACTS_REGISTER", NO_VERSION_CONTROL),
            IAddressProviderV3(_oldAddressProvider).getAddressOrRevert("TREASURY", NO_VERSION_CONTROL),
            _name,
            _vetoAdmin
        )
    {
        /// Convert existing pools into markets
        address priceOracle = IAddressProviderV3(_oldAddressProvider).getAddressOrRevert("PRICE_ORACLE", 300);

        address[] memory _pools = pools();
        uint256 len = _pools.length;

        for (uint256 i; i < len; i++) {
            address pool = _pools[i];

            priceOracles[pool] = priceOracle;
            IAddressProviderV3(addressProvider).registerPool(pool);
            emit CreateMarket(pool, IPoolV3(pool).asset(), IPoolV3(pool).name(), IPoolV3(pool).symbol());
        }

        // import degenNFT
        address degenNFT = IAddressProviderV3(_oldAddressProvider).getAddressOrRevert("DEGEN_NFT", 1);
        _degenNFTs.add(degenNFT);
        emit DeployDegenNFT(degenNFT);
    }

    //
    function pools() public view override returns (address[] memory) {
        address[] memory _pools = IContractsRegister(contractsRegister).getPools();
        uint256 len = _pools.length;
        uint256 v3count;
        address[] memory _v3pools = new address[](len);
        for (uint256 i; i < len; i++) {
            address p = _pools[i];
            if (IVersion(p).version() > 3_00) {
                _v3pools[v3count] = p;
                v3count++;
            }
        }

        assembly {
            mstore(_v3pools, v3count)
        }

        return _v3pools;
    }
}
