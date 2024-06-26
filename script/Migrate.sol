// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Script.sol";
import {IAddressProviderV3} from "../contracts/interfaces/IAddressProviderV3.sol";
import {AddressProviderV3} from "../contracts/global/AddressProviderV3.sol";

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
} from "../contracts/libraries/ContractLiterals.sol";
import {IACL} from "../contracts/interfaces/IACL.sol";
import {MarketConfiguratorLegacy} from "../contracts/market/MarketConfiguratorLegacy.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

import {InterestModelFactory} from "../contracts/factories/InterestModelFactory.sol";
import {PoolFactoryV3} from "../contracts/factories/PoolFactoryV3.sol";
import {CreditFactoryV3} from "../contracts/factories/CreditFactoryV3.sol";
import {PriceOracleFactoryV3} from "../contracts/factories/PriceOracleFactoryV3.sol";
import {MarketConfiguratorFactoryV3} from "../contracts/factories/MarketConfiguratorFactoryV3.sol";
import {AdapterFactoryV3} from "../contracts/factories/AdapterFactoryV3.sol";

struct APMigration {
    string name;
    uint256 version;
}

address constant emergencyLiquidator = 0x7BD9c8161836b1F402233E80F55E3CaE0Fde4d87;

contract Migrate is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address oldAddressProvider = vm.envAddress("ADDRESS_PROVIDER");
        address vetoAdmin = vm.envAddress("VETO_ADMIN");

        address acl = IAddressProviderV3(oldAddressProvider).getAddressOrRevert("ACL", NO_VERSION_CONTROL);

        vm.startBroadcast(deployerPrivateKey);
        AddressProviderV3 _addressProvider = new AddressProviderV3();
        _addressProvider.transferOwnership(IACL(acl).owner());

        /// AddressProvider migration
        APMigration[16] memory migrations = [
            APMigration({name: "WETH_TOKEN", version: 0}),
            APMigration({name: "GEAR_TOKEN", version: 0}),
            APMigration({name: "BOT_LIST", version: 0}),
            APMigration({name: "GEAR_STAKING", version: 300}),
            APMigration({name: "DEGEN_NFT", version: 1}),
            APMigration({name: "ACCOUNT_FACTORY", version: 0}),
            APMigration({name: "INFLATION_ATTACK_BLOCKER", version: 300}),
            APMigration({name: "ROUTER", version: 302}),
            APMigration({name: "ZERO_PRICE_FEED", version: 0}),
            APMigration({name: "ZAPPER_REGISTER", version: 300}),
            APMigration({name: "MULTI_PAUSE", version: 0}),
            APMigration({name: "DEGEN_DISTRIBUTOR", version: 300}),
            APMigration({name: "PARTIAL_LIQUIDATION_BOT", version: 300}),
            APMigration({name: "DELEVERAGE_BOT_PEGGED", version: 300}),
            APMigration({name: "DELEVERAGE_BOT_LV", version: 300}),
            APMigration({name: "DELEVERAGE_BOT_HV", version: 300})
        ];

        uint256 len = migrations.length;

        for (uint256 i; i < len; i++) {
            address oldAddress =
                IAddressProviderV3(oldAddressProvider).getAddressOrRevert(migrations[i].name, migrations[i].version);
            _addressProvider.setAddress({
                key: migrations[i].name,
                value: oldAddress,
                saveVersion: migrations[i].version != NO_VERSION_CONTROL
            });
        }

        /// Deploy new factories

        address factory = address(new InterestModelFactory());
        _addressProvider.setAddress("INTEREST_MODEL_FACTORY", factory, true);

        factory = address(new PoolFactoryV3(address(_addressProvider)));
        _addressProvider.setAddress("POOL_FACTORY", factory, true);

        factory = address(new CreditFactoryV3(address(_addressProvider)));
        _addressProvider.setAddress("CREDIT_FACTORY", factory, true);

        factory = address(new PriceOracleFactoryV3(address(_addressProvider)));
        _addressProvider.setAddress("PRICE_ORACLE_FACTORY", factory, true);

        factory = address(new MarketConfiguratorFactoryV3(address(_addressProvider)));
        _addressProvider.setAddress("MARKET_CONFIGURATOR_FACTORY", factory, true);

        factory = address(new AdapterFactoryV3());
        _addressProvider.setAddress("ADAPTER_FACTORY", factory, true);

        /// Deploy MarketConfiguratorLegacy
        bytes memory bytecode = type(MarketConfiguratorLegacy).creationCode;
        bytes memory parameters =
            abi.encode(oldAddressProvider, address(_addressProvider), "Market Configurator", vetoAdmin);

        bytes32 bytecodeHash = keccak256(abi.encodePacked(bytecode, parameters));
        address mcl = Create2.computeAddress(0, bytecodeHash);

        /// Register this marketConfigurator in AddressProvider
        _addressProvider.addMarketConfigurator(address(mcl));

        /// Deploy MarketConfiguratorLegacy
        Create2.deploy(0, 0, bytecode);

        vm.stopBroadcast();
    }
}
